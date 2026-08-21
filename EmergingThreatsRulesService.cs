using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net.Http;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

#if !BUILD_WITHOUT_FIDDLER
using Fiddler;
#endif

namespace DomainReputationInspector
{
    /// <summary>
    /// Service for managing Emerging Threats (ET) rules and domain lookups
    /// Supports both ET Open (free) and ET Pro (commercial) rule sets
    /// </summary>
    public class EmergingThreatsRulesService : IDisposable
    {
        #region Private Fields

        private readonly HttpClient _httpClient;
        private SQLiteConnection _database;
        private Timer _updateTimer;
        private readonly SemaphoreSlim _updateSemaphore = new SemaphoreSlim(1, 1);
        private readonly ConcurrentDictionary<string, ETDomainInfo> _etCache = 
            new ConcurrentDictionary<string, ETDomainInfo>();
        private readonly DomainExtractor _domainExtractor = new DomainExtractor();

        // ET Pro API key (optional - falls back to ET Open if not provided)
        private string _etProApiKey;
        
        // Update schedule - daily at 2 AM
        private DateTime _lastUpdateTime = DateTime.MinValue;
        private readonly TimeSpan _updateInterval = TimeSpan.FromDays(1); // Daily updates
        private readonly TimeSpan _updateCheckInterval = TimeSpan.FromHours(1); // Check every hour for daily update time

        private bool _disposed = false;
        private bool _initializationComplete = false;
        private bool _didInitialUpdate = false;

        // Official ET rule archive URLs (as per documentation)
        private const string ET_OPEN_ARCHIVE_URL = "https://rules.emergingthreats.net/open/snort-2.9.0/emerging.rules.tar.gz";
        private const string ET_PRO_ARCHIVE_URL = "https://rules.emergingthreatspro.com/{KEY}/snort-2.9.0/etpro.rules.tar.gz";

        #endregion

        #region Helper Classes
        
        // Helper class for post-extraction decisions (avoiding C# 7.0 tuples for .NET Framework 4.6.1 compatibility)
        private class PostExtractionDecision
        {
            public bool ShouldInclude { get; set; }
            public string Reason { get; set; }
            public string ModifiedDomain { get; set; }
            
            public PostExtractionDecision(bool shouldInclude, string reason = null, string modifiedDomain = null)
            {
                ShouldInclude = shouldInclude;
                Reason = reason;
                ModifiedDomain = modifiedDomain;
            }
        }

        #endregion

        #region Constructor and Disposal

        public EmergingThreatsRulesService()
        {
            // IMMEDIATE logging to test if constructor starts
            try
            {
#if !BUILD_WITHOUT_FIDDLER
                FiddlerApplication.Log.LogString("[ET-RULES-CONSTRUCTOR] EmergingThreatsRulesService constructor STARTING");
#endif
                _httpClient = new HttpClient();
                _httpClient.Timeout = TimeSpan.FromMinutes(5);
                
                LogMessage("ET RULES: Starting service initialization...");
                InitializeDatabase();
                LoadSettings();

                // Mark initialization as complete
                _initializationComplete = true;
                LogMessage("ET RULES: Service initialized - Daily updates enabled");
                
                // Initial download only when DB is empty or LastUpdateTime is stale
                Task.Run(async () =>
                {
                    try
                    {
                        if (!_didInitialUpdate)
                        {
                            _didInitialUpdate = true;
                            if (NeedsInitialDownload())
                            {
                                LogMessage("ET RULES: Starting initial rules download after initialization");
                                await DownloadAndParseAllRulesAsync();
                            }
                            else
                            {
                                LogMessage("ET RULES: Recent rules present - skipping initial download");
                                WarmMemoryCacheFromDatabase();
                            }
                        }
                        else
                        {
                            LogMessage("ET RULES: Skipping duplicate initial update");
                        }
                    }
                    catch (Exception ex)
                    {
                        LogMessage($"ET RULES ERROR: Initial update failed: {ex.Message}");
                    }
                    finally
                    {
                        // Start background update timer ONLY after initial download/cache warm completes
                        _updateTimer = new Timer(CheckForDailyUpdate, null, _updateCheckInterval, _updateCheckInterval);
                        LogMessage("ET RULES: Background update timer started");
                    }
                });
            }
            catch (Exception ex)
            {
                LogMessage($"ET RULES ERROR: Service initialization failed: {ex.Message}");
                LogMessage($"ET RULES ERROR: Stack trace: {ex.StackTrace}");
                LogMessage($"ET RULES ERROR: Exception type: {ex.GetType().Name}");
                if (ex.InnerException != null)
                {
                    LogMessage($"ET RULES ERROR: Inner exception: {ex.InnerException.Message}");
                }
                throw; // Re-throw to ensure the service is marked as failed
            }
        }

        private string BuildEtProUrl(string baseUrl)
        {
            try
            {
                if (string.IsNullOrEmpty(_etProApiKey)) return baseUrl;

                // Replace {KEY} placeholder with actual API key
                return baseUrl.Replace("{KEY}", Uri.EscapeDataString(_etProApiKey));
            }
            catch
            {
                return baseUrl;
            }
        }

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;

            try
            {
                _updateTimer?.Dispose();
                _updateSemaphore?.Dispose();
                _httpClient?.Dispose();
                _domainExtractor?.Dispose();
                _database?.Close();
                _database?.Dispose();
            }
            catch (Exception ex)
            {
                LogMessage($"ET RULES ERROR: Disposal error: {ex.Message}");
            }
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Sets the ET Pro API key and saves it to settings
        /// </summary>
        /// <param name="apiKey">The ET Pro API key (can be null/empty for ET Open only)</param>
        public void SetETProApiKey(string apiKey)
        {
            _etProApiKey = apiKey?.Trim();
            SaveSettings();
            
            if (string.IsNullOrEmpty(_etProApiKey))
            {
                LogMessage("ET RULES: Using ET Open rule set (free)");
            }
            else
            {
                LogMessage($"ET RULES: ET Pro key configured (length: {_etProApiKey.Length}) - will attempt to use ET Pro rules");
                LogMessage($"ET RULES: Current statistics: {GetStatistics()}");
            }
        }

        /// <summary>
        /// Gets the current ET Pro API key
        /// </summary>
        /// <returns>The ET Pro API key or empty string if not set</returns>
        public string GetETProApiKey()
        {
            return _etProApiKey ?? string.Empty;
        }

        /// <summary>
        /// Checks if a domain is in the ET rules database
        /// </summary>
        /// <param name="domain">The domain to check</param>
        /// <returns>ET domain information if found, null otherwise</returns>
        public ETDomainInfo CheckDomain(string domain)
        {
            if (string.IsNullOrEmpty(domain) || _disposed)
                return null;

            try
            {
                // Check memory cache first (fastest - ~0.1ms)
                if (_etCache.TryGetValue(domain, out ETDomainInfo cachedInfo))
                {
                    return cachedInfo;
                }

                // Check database with EXACT domain matching only
                // This ensures phishing domains like "linkedin-phish.com" don't flag "linkedin.com"
                using (var command = new SQLiteCommand(@"
                    SELECT RuleId, Description, Classification, Severity, RuleSource, LastUpdated, Domain
                    FROM ET_Domain_Indicators 
                    WHERE Domain = @domain AND IsActive = 1 
                    ORDER BY 
                        CASE Severity 
                            WHEN 'high' THEN 1 
                            WHEN 'medium' THEN 2 
                            WHEN 'low' THEN 3 
                            ELSE 4 
                        END,
                        RuleId DESC
                    LIMIT 1", _database))
                {
                    command.Parameters.AddWithValue("@domain", domain);

                    using (var reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            int ordRuleId = reader.GetOrdinal("RuleId");
                            int ordDesc = reader.GetOrdinal("Description");
                            int ordClass = reader.GetOrdinal("Classification");
                            int ordSev = reader.GetOrdinal("Severity");
                            int ordSrc = reader.GetOrdinal("RuleSource");
                            int ordLU = reader.GetOrdinal("LastUpdated");
                            int ordDomain = reader.GetOrdinal("Domain");

                            var originalDomain = reader.IsDBNull(ordDomain) ? domain : reader.GetString(ordDomain);
                            
                            var etInfo = new ETDomainInfo
                            {
                                Domain = domain, // Use the exact queried domain
                                RuleId = reader.IsDBNull(ordRuleId) ? 0 : reader.GetInt32(ordRuleId),
                                Description = reader.IsDBNull(ordDesc) ? null : reader.GetString(ordDesc),
                                Classification = reader.IsDBNull(ordClass) ? null : reader.GetString(ordClass),
                                Severity = reader.IsDBNull(ordSev) ? null : reader.GetString(ordSev),
                                Source = reader.IsDBNull(ordSrc) ? null : reader.GetString(ordSrc),
                                LastUpdated = reader.IsDBNull(ordLU) ? DateTime.MinValue : reader.GetDateTime(ordLU)
                            };

                            // Cache for future lookups
                            _etCache.TryAdd(domain, etInfo);

                            return etInfo;
                        }
                    }
                }

                // Cache negative result to avoid repeated DB queries
                _etCache.TryAdd(domain, null);
                return null;
            }
            catch (Exception ex)
            {
                LogMessage($"ET RULES ERROR: Lookup failed for {domain}: {ex.Message}");
                return null;
            }
        }

        /// <summary>
        /// Forces an immediate update of ET rules
        /// </summary>
        /// <returns>True if update was successful</returns>
        public async Task<bool> ForceUpdateAsync()
        {
            try
            {
                LogMessage("ET RULES: Force update requested");
                
                // Use semaphore to prevent concurrent updates
                await _updateSemaphore.WaitAsync();
                
                try
                {
                    await DownloadAndParseAllRulesAsync();
                    return true;
                }
                finally
                {
                    _updateSemaphore.Release();
                }
            }
            catch (Exception ex)
            {
                LogMessage($"ET RULES ERROR: Force update failed: {ex.Message}");
                return false;
            }
        }

        /// <summary>
        /// Gets statistics about the ET rules database
        /// </summary>
        /// <returns>Statistics string</returns>
        public string GetStatistics()
        {
            try
            {
                // Check if database and table are ready
                if (_database == null)
                {
                    return "ET Rules: Database not initialized";
                }

                // Check if table exists before querying
                using (var tableCheckCommand = new SQLiteCommand("SELECT name FROM sqlite_master WHERE type='table' AND name='ET_Domain_Indicators'", _database))
                {
                    var tableExists = tableCheckCommand.ExecuteScalar();
                    if (tableExists == null)
                    {
                        return "ET Rules: No rules data available";
                    }
                }

                using (var command = new SQLiteCommand(@"
                    SELECT 
                        COUNT(*) as TotalRules,
                        COUNT(CASE WHEN Severity = 'high' THEN 1 END) as HighSeverity,
                        COUNT(CASE WHEN Severity = 'medium' THEN 1 END) as MediumSeverity,
                        COUNT(CASE WHEN Severity = 'low' THEN 1 END) as LowSeverity,
                        MAX(LastUpdated) as LastUpdate
                    FROM ET_Domain_Indicators 
                    WHERE IsActive = 1", _database))
                {
                    using (var reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            int ordTotal = reader.GetOrdinal("TotalRules");
                            int ordHigh = reader.GetOrdinal("HighSeverity");
                            int ordMed = reader.GetOrdinal("MediumSeverity");
                            int ordLow = reader.GetOrdinal("LowSeverity");
                            int ordLU = reader.GetOrdinal("LastUpdate");

                            var total = reader.IsDBNull(ordTotal) ? 0 : reader.GetInt32(ordTotal);
                            var high = reader.IsDBNull(ordHigh) ? 0 : reader.GetInt32(ordHigh);
                            var medium = reader.IsDBNull(ordMed) ? 0 : reader.GetInt32(ordMed);
                            var low = reader.IsDBNull(ordLow) ? 0 : reader.GetInt32(ordLow);
                            var lastUpdate = reader.IsDBNull(ordLU) ? "Never" : reader.GetDateTime(ordLU).ToString("yyyy-MM-dd HH:mm");

                            // Determine actual rule source based on database content
                            var ruleSource = "ET Open";
                            if (!string.IsNullOrEmpty(_etProApiKey))
                            {
                                try
                                {
                                    using (var sourceCheck = new SQLiteCommand("SELECT COUNT(*) FROM ET_Domain_Indicators WHERE RuleSource LIKE '%ET Pro%' AND IsActive = 1", _database))
                                    {
                                        var etProCount = Convert.ToInt32(sourceCheck.ExecuteScalar());
                                        ruleSource = etProCount > 0 ? "ET Pro" : "ET Open (ET Pro configured)";
                                    }
                                }
                                catch
                                {
                                    ruleSource = "ET Open";
                                }
                            }
                            
                            return $"ET Rules: {total} domains ({high} high, {medium} medium, {low} low) | Source: {ruleSource} | Last Update: {lastUpdate}";
                        }
                    }
                }

                return "ET Rules: No data available";
            }
            catch (Exception ex)
            {
                LogMessage($"ET RULES ERROR: Statistics failed: {ex.Message}");
                return "ET Rules: Error retrieving statistics";
            }
        }

        #endregion

        #region Private Methods

        private void MigrateDatabaseSchema()
        {
            try
            {
                LogMessage("ET RULES: MigrateDatabaseSchema() - Starting");
                
                // First check if table exists
                LogMessage("ET RULES: Checking if ET_Domain_Indicators table exists");
                using (var tableCheckCommand = new SQLiteCommand("SELECT name FROM sqlite_master WHERE type='table' AND name='ET_Domain_Indicators'", _database))
                {
                    var tableExists = tableCheckCommand.ExecuteScalar();
                    LogMessage($"ET RULES: Table check result: {tableExists}");
                    
                    if (tableExists == null)
                    {
                        LogMessage("ET RULES: ET_Domain_Indicators table does not exist - no migration needed");
                        return;
                    }
                    LogMessage("ET RULES: ET_Domain_Indicators table exists, proceeding with column check");
                }
                
                // Check if MainDomain column exists
                LogMessage("ET RULES: About to execute PRAGMA table_info");
                bool hasMainDomain = false;
                using (var command = new SQLiteCommand("PRAGMA table_info(ET_Domain_Indicators)", _database))
                {
                    LogMessage("ET RULES: PRAGMA command created, about to execute");
                    using (var reader = command.ExecuteReader())
                    {
                        LogMessage("ET RULES: PRAGMA executed, reading results");
                        while (reader.Read())
                        {
                            // PRAGMA table_info returns: cid, name, type, notnull, dflt_value, pk
                            var columnName = reader.GetString(1); // name is at index 1
                            LogMessage($"ET RULES: Found column: {columnName}");
                            
                            if (columnName.Equals("MainDomain", StringComparison.OrdinalIgnoreCase))
                            {
                                hasMainDomain = true;
                                LogMessage("ET RULES: MainDomain column already exists");
                                break;
                            }
                        }
                        LogMessage("ET RULES: Finished reading PRAGMA results");
                    }
                }

                if (!hasMainDomain)
                {
                    LogMessage("ET RULES: MainDomain column not found - starting migration");
                    
                    // Perform migration in a single transaction for consistency
                    using (var transaction = _database.BeginTransaction())
                    {
                        try
                        {
                            // Add MainDomain column
                            LogMessage("ET RULES: Adding MainDomain column...");
                            using (var alterCommand = new SQLiteCommand("ALTER TABLE ET_Domain_Indicators ADD COLUMN MainDomain TEXT", _database, transaction))
                            {
                                alterCommand.ExecuteNonQuery();
                            }
                            LogMessage("ET RULES: MainDomain column added successfully");

                            // Create index for MainDomain (now that column exists)
                            LogMessage("ET RULES: Creating MainDomain index...");
                            using (var indexCommand = new SQLiteCommand("CREATE INDEX IF NOT EXISTS idx_main_domain ON ET_Domain_Indicators(MainDomain)", _database, transaction))
                            {
                                indexCommand.ExecuteNonQuery();
                            }
                            LogMessage("ET RULES: MainDomain index created successfully");

                            // Update existing records to populate MainDomain within the same transaction
                            LogMessage("ET RULES: Updating existing records...");
                            UpdateExistingMainDomainsInTransaction(transaction);
                            
                            // Commit the transaction
                            transaction.Commit();
                            LogMessage("ET RULES: Database migration completed successfully");
                        }
                        catch (Exception)
                        {
                            transaction.Rollback();
                            throw;
                        }
                    }
                }
                else
                {
                    LogMessage("ET RULES: No migration needed - schema is up to date");
                }
            }
            catch (Exception ex)
            {
                LogMessage($"ET RULES ERROR: Database migration failed: {ex.Message}");
                LogMessage($"ET RULES ERROR: Stack trace: {ex.StackTrace}");
                throw; // Re-throw to ensure initialization fails if migration fails
            }
        }

        private void UpdateExistingMainDomains()
        {
            try
            {
                // Update existing records to set MainDomain = Domain (exact match only)
                // This ensures no normalization of malicious domains
                // NOTE: MainDomain column was just added, so query all existing records
                using (var selectCommand = new SQLiteCommand("SELECT Id, Domain FROM ET_Domain_Indicators", _database))
                using (var reader = selectCommand.ExecuteReader())
                {
                    var updates = new List<DomainUpdate>();
                    
                    while (reader.Read())
                    {
                        var id = reader.GetInt32(0);    // Id is first column
                        var domain = reader.GetString(1); // Domain is second column
                        
                        // CRITICAL: Set MainDomain = Domain (no normalization)
                        // This preserves exact malicious domains like "linkedin-phish.com"
                        updates.Add(new DomainUpdate { Id = id, Domain = domain });
                    }
                    
                    reader.Close();
                    
                    // Apply updates - set MainDomain = Domain for all existing records
                    foreach (var update in updates)
                    {
                        using (var updateCommand = new SQLiteCommand("UPDATE ET_Domain_Indicators SET MainDomain = @domain WHERE Id = @id", _database))
                        {
                            updateCommand.Parameters.AddWithValue("@domain", update.Domain);
                            updateCommand.Parameters.AddWithValue("@id", update.Id);
                            updateCommand.ExecuteNonQuery();
                        }
                    }
                    
                    if (updates.Count > 0)
                    {
                        LogMessage($"ET RULES: Updated {updates.Count} existing records with exact domain preservation");
                    }
                }
            }
            catch (Exception ex)
            {
                LogMessage($"ET RULES ERROR: Failed to update existing domains: {ex.Message}");
            }
        }

        private void UpdateExistingMainDomainsInTransaction(SQLiteTransaction transaction)
        {
            try
            {
                // Update existing records to set MainDomain = Domain within the migration transaction
                using (var selectCommand = new SQLiteCommand("SELECT Id, Domain FROM ET_Domain_Indicators", _database, transaction))
                using (var reader = selectCommand.ExecuteReader())
                {
                    var updates = new List<DomainUpdate>();
                    
                    while (reader.Read())
                    {
                        var id = reader.GetInt32(0);    // Id is first column
                        var domain = reader.GetString(1); // Domain is second column
                        
                        // CRITICAL: Set MainDomain = Domain (no normalization)
                        // This preserves exact malicious domains like "linkedin-phish.com"
                        updates.Add(new DomainUpdate { Id = id, Domain = domain });
                    }
                    
                    reader.Close();
                    
                    // Apply updates within the same transaction
                    foreach (var update in updates)
                    {
                        using (var updateCommand = new SQLiteCommand("UPDATE ET_Domain_Indicators SET MainDomain = @domain WHERE Id = @id", _database, transaction))
                        {
                            updateCommand.Parameters.AddWithValue("@domain", update.Domain);
                            updateCommand.Parameters.AddWithValue("@id", update.Id);
                            updateCommand.ExecuteNonQuery();
                        }
                    }
                    
                    if (updates.Count > 0)
                    {
                        LogMessage($"ET RULES: Updated {updates.Count} existing records with exact domain preservation");
                    }
                }
            }
            catch (Exception ex)
            {
                LogMessage($"ET RULES ERROR: Failed to update existing domains in transaction: {ex.Message}");
                throw; // Re-throw to trigger transaction rollback
            }
        }

        private void InitializeDatabase()
        {
            try
            {
                LogMessage("ET RULES: InitializeDatabase() - Starting");
                
                var dbPath = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData),
                    "DomainReputationInspector",
                    "et_rules.db"
                );
                LogMessage($"ET RULES: Database path: {dbPath}");

                Directory.CreateDirectory(Path.GetDirectoryName(dbPath));
                LogMessage("ET RULES: Directory created");

                _database = new SQLiteConnection($"Data Source={dbPath}");
                LogMessage("ET RULES: SQLite connection created");
                
                _database.Open();
                LogMessage("ET RULES: Database opened successfully");

                // Create tables without MainDomain initially (for backward compatibility)
                var createTablesCommand = @"
                    CREATE TABLE IF NOT EXISTS ET_Domain_Indicators (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        Domain TEXT NOT NULL,
                        RuleId INTEGER,
                        Description TEXT,
                        Classification TEXT,
                        Severity TEXT,
                        RuleSource TEXT,
                        FirstSeen DATETIME,
                        LastUpdated DATETIME,
                        IsActive BOOLEAN DEFAULT 1
                    );

                    CREATE INDEX IF NOT EXISTS idx_domain ON ET_Domain_Indicators(Domain);
                    CREATE INDEX IF NOT EXISTS idx_severity ON ET_Domain_Indicators(Severity);
                    CREATE INDEX IF NOT EXISTS idx_classification ON ET_Domain_Indicators(Classification);
                    CREATE INDEX IF NOT EXISTS idx_rule_source ON ET_Domain_Indicators(RuleSource);

                    CREATE TABLE IF NOT EXISTS ET_Update_Log (
                        Id INTEGER PRIMARY KEY AUTOINCREMENT,
                        UpdateTime DATETIME,
                        RuleSource TEXT,
                        RulesCount INTEGER,
                        Success BOOLEAN,
                        ErrorMessage TEXT
                    );

                    CREATE TABLE IF NOT EXISTS ET_Settings (
                        Key TEXT PRIMARY KEY,
                        Value TEXT
                    );
                ";

                LogMessage("ET RULES: About to execute CREATE TABLE statements");
                using (var command = new SQLiteCommand(createTablesCommand, _database))
                {
                    command.ExecuteNonQuery();
                }
                LogMessage("ET RULES: CREATE TABLE statements executed successfully");

                LogMessage("ET RULES: Starting database migration check");
                
                // Migrate existing database to add MainDomain column if it doesn't exist
                MigrateDatabaseSchema();
                LogMessage("ET RULES: MigrateDatabaseSchema() completed");

                // Purge soft-deleted history / exact dupes, then enforce unique Domain+RuleId
                PurgeDuplicateAndInactiveIndicators();
                EnsureUniqueDomainRuleIndex();

                LogMessage("ET RULES: Database initialized and migration completed");
            }
            catch (Exception ex)
            {
                LogMessage($"ET RULES ERROR: Database initialization failed: {ex.Message}");
                throw;
            }
        }

        private int GetActiveIndicatorCount()
        {
            try
            {
                if (_database == null)
                    return 0;

                using (var command = new SQLiteCommand(
                    "SELECT COUNT(*) FROM ET_Domain_Indicators WHERE IsActive = 1", _database))
                {
                    return Convert.ToInt32(command.ExecuteScalar());
                }
            }
            catch
            {
                return 0;
            }
        }

        private bool NeedsInitialDownload()
        {
            if (GetActiveIndicatorCount() <= 0)
                return true;

            if (_lastUpdateTime == DateTime.MinValue)
                return true;

            if (DateTime.Now - _lastUpdateTime >= _updateInterval)
                return true;

            return false;
        }

        private void PurgeDuplicateAndInactiveIndicators()
        {
            try
            {
                int totalBefore;
                int inactiveBefore;
                using (var totalCmd = new SQLiteCommand("SELECT COUNT(*) FROM ET_Domain_Indicators", _database))
                {
                    totalBefore = Convert.ToInt32(totalCmd.ExecuteScalar());
                }
                using (var inactiveCmd = new SQLiteCommand(
                    "SELECT COUNT(*) FROM ET_Domain_Indicators WHERE IsActive = 0", _database))
                {
                    inactiveBefore = Convert.ToInt32(inactiveCmd.ExecuteScalar());
                }

                if (totalBefore == 0)
                {
                    LogMessage("ET RULES: No indicators to purge");
                    return;
                }

                int deletedInactive = 0;
                int deletedDupes = 0;

                using (var transaction = _database.BeginTransaction())
                {
                    using (var deleteInactive = new SQLiteCommand(
                        "DELETE FROM ET_Domain_Indicators WHERE IsActive = 0", _database, transaction))
                    {
                        deletedInactive = deleteInactive.ExecuteNonQuery();
                    }

                    // Keep one row per Domain+RuleId after inactive purge
                    using (var deleteDupes = new SQLiteCommand(@"
                        DELETE FROM ET_Domain_Indicators
                        WHERE Id NOT IN (
                            SELECT MAX(Id) FROM ET_Domain_Indicators GROUP BY Domain, RuleId
                        )", _database, transaction))
                    {
                        deletedDupes = deleteDupes.ExecuteNonQuery();
                    }

                    transaction.Commit();
                }

                int totalAfter;
                using (var totalCmd = new SQLiteCommand("SELECT COUNT(*) FROM ET_Domain_Indicators", _database))
                {
                    totalAfter = Convert.ToInt32(totalCmd.ExecuteScalar());
                }

                LogMessage($"ET RULES: Purge complete - before={totalBefore}, inactive={inactiveBefore}, deletedInactive={deletedInactive}, deletedDupes={deletedDupes}, after={totalAfter}");

                // One-shot VACUUM only when a large purge freed significant space
                if (deletedInactive + deletedDupes >= 1000)
                {
                    LogMessage("ET RULES: Running one-shot VACUUM after large purge");
                    using (var vacuum = new SQLiteCommand("VACUUM", _database))
                    {
                        vacuum.ExecuteNonQuery();
                    }
                    LogMessage("ET RULES: VACUUM completed");
                }
            }
            catch (Exception ex)
            {
                LogMessage($"ET RULES ERROR: Purge of duplicate/inactive indicators failed: {ex.Message}");
            }
        }

        private void EnsureUniqueDomainRuleIndex()
        {
            try
            {
                using (var command = new SQLiteCommand(
                    "CREATE UNIQUE INDEX IF NOT EXISTS idx_domain_ruleid ON ET_Domain_Indicators(Domain, RuleId)",
                    _database))
                {
                    command.ExecuteNonQuery();
                }
                LogMessage("ET RULES: Unique index idx_domain_ruleid ready");
            }
            catch (Exception ex)
            {
                LogMessage($"ET RULES ERROR: Failed to create unique Domain+RuleId index: {ex.Message}");
            }
        }

        private void LoadSettings()
        {
            try
            {
                LogMessage("ET RULES: LoadSettings() - Starting");
                using (var command = new SQLiteCommand("SELECT Value FROM ET_Settings WHERE Key = 'ETProApiKey'", _database))
                {
                    var result = command.ExecuteScalar();
                    _etProApiKey = result?.ToString() ?? string.Empty;
                }

                // Load last update time
                using (var updateCommand = new SQLiteCommand("SELECT Value FROM ET_Settings WHERE Key = 'LastUpdateTime'", _database))
                {
                    var updateResult = updateCommand.ExecuteScalar();
                    if (updateResult != null && DateTime.TryParse(updateResult.ToString(), out DateTime lastUpdate))
                    {
                        _lastUpdateTime = lastUpdate;
                    }
                }

                LogMessage($"ET RULES: Settings loaded - API key: {(string.IsNullOrEmpty(_etProApiKey) ? "Not set (using ET Open)" : "Set (using ET Pro)")}");
                LogMessage("ET RULES: LoadSettings() - Completed successfully");
            }
            catch (Exception ex)
            {
                LogMessage($"ET RULES ERROR: Settings load failed: {ex.Message}");
            }
        }

        private void SaveSettings()
        {
            try
            {
                using (var command = new SQLiteCommand(@"
                    INSERT OR REPLACE INTO ET_Settings (Key, Value) 
                    VALUES ('ETProApiKey', @apiKey)", _database))
                {
                    command.Parameters.AddWithValue("@apiKey", _etProApiKey ?? string.Empty);
                    command.ExecuteNonQuery();
                }

                using (var updateCommand = new SQLiteCommand(@"
                    INSERT OR REPLACE INTO ET_Settings (Key, Value) 
                    VALUES ('LastUpdateTime', @lastUpdate)", _database))
                {
                    updateCommand.Parameters.AddWithValue("@lastUpdate", _lastUpdateTime.ToString("O"));
                    updateCommand.ExecuteNonQuery();
                }

                LogMessage("ET RULES: Settings saved");
            }
            catch (Exception ex)
            {
                LogMessage($"ET RULES ERROR: Settings save failed: {ex.Message}");
            }
        }

        private async void CheckForDailyUpdate(object state)
        {
            if (_disposed)
                return;

            try
            {
                await _updateSemaphore.WaitAsync();

                var now = DateTime.Now;
                var shouldUpdate = false;

                // Check if initial load is needed
                if (_lastUpdateTime == DateTime.MinValue)
                {
                    LogMessage("ET RULES: Initial rules download required");
                    shouldUpdate = true;
                }
                else
                {
                    var timeSinceLastUpdate = now - _lastUpdateTime;
                    
                    // Check if it's been more than 24 hours since last update
                    if (timeSinceLastUpdate >= _updateInterval)
                    {
                        // Prefer to update between 2-3 AM, but don't wait indefinitely
                        if ((now.Hour >= 2 && now.Hour < 3) || timeSinceLastUpdate.TotalHours > 25)
                        {
                            LogMessage($"ET RULES: Daily update time reached (last update: {timeSinceLastUpdate.TotalHours:F1}h ago)");
                            shouldUpdate = true;
                        }
                    }
                }

                if (shouldUpdate)
                {
                    await DownloadAndParseAllRulesAsync();
                }
            }
            catch (Exception ex)
            {
                LogMessage($"ET RULES ERROR: Daily update check failed: {ex.Message}");
            }
            finally
            {
                _updateSemaphore.Release();
            }
        }

        private async Task DownloadAndParseAllRulesAsync()
        {
            try
            {
                var ruleSource = string.IsNullOrEmpty(_etProApiKey) ? "ET Open" : "ET Pro";
                LogMessage($"ET RULES: Starting daily rules update from {ruleSource}");

                var allIndicators = new List<ETDomainIndicator>();

                // Use official tar.gz archives as per ET documentation
                if (string.IsNullOrEmpty(_etProApiKey))
                {
                    // Download ET Open archive
                    var success = await DownloadAndExtractArchive(ET_OPEN_ARCHIVE_URL, "ET Open", allIndicators);
                    if (!success)
                    {
                        LogMessage("ET RULES ERROR: Failed to download ET Open archive");
                    }
                }
                else
                {
                    // Try ET Pro archive first
                    var etProUrl = BuildEtProUrl(ET_PRO_ARCHIVE_URL);
                    var success = await DownloadAndExtractArchive(etProUrl, "ET Pro", allIndicators);
                    if (!success)
                    {
                        LogMessage("ET RULES: ET Pro archive failed, falling back to ET Open");
                        ruleSource = "ET Open (ET Pro fallback)";
                        await DownloadAndExtractArchive(ET_OPEN_ARCHIVE_URL, ruleSource, allIndicators);
                    }
                }

                if (allIndicators.Count > 0)
                {
                    await StoreDomainIndicatorsAsync(allIndicators, ruleSource);
                    UpdateMemoryCache(allIndicators);
                    
                    _lastUpdateTime = DateTime.Now;
                    SaveSettings();
                    
                    LogMessage($"ET RULES: Daily update completed successfully - {allIndicators.Count} total indicators from {ruleSource}");
                }
                else
                {
                    LogMessage("ET RULES ERROR: No indicators found in any rule set");
                }
            }
            catch (Exception ex)
            {
                LogMessage($"ET RULES ERROR: Daily update failed: {ex.Message}");
                
                // Log the failure
                await LogUpdateResult(0, false, ex.Message);
            }
        }

        private async Task<bool> DownloadAndExtractArchive(string archiveUrl, string source, List<ETDomainIndicator> allIndicators)
        {
            try
            {
                LogMessage($"ET RULES: Downloading {source} archive from {archiveUrl}");
                
                var response = await _httpClient.GetAsync(archiveUrl);
                
                if (!response.IsSuccessStatusCode)
                {
                    LogMessage($"ET RULES ERROR: Failed to download {source} archive - Status: {response.StatusCode}");
                    return false;
                }
                
                var archiveData = await response.Content.ReadAsByteArrayAsync();
                LogMessage($"ET RULES: Downloaded {archiveData.Length} bytes of {source} archive");
                
                // Extract and parse the tar.gz content
                var extractedIndicators = await ExtractAndParseArchive(archiveData, source);
                if (extractedIndicators.Count > 0)
                {
                    allIndicators.AddRange(extractedIndicators);
                    LogMessage($"ET RULES: Successfully extracted {extractedIndicators.Count} indicators from {source} archive");
                    return true;
                }
                else
                {
                    LogMessage($"ET RULES: No indicators found in {source} archive");
                    return false;
                }
            }
            catch (Exception ex)
            {
                LogMessage($"ET RULES ERROR: Failed to download/extract {source} archive: {ex.Message}");
                return false;
            }
        }

        private async Task<List<ETDomainIndicator>> ExtractAndParseArchive(byte[] archiveData, string source)
        {
            var indicators = new List<ETDomainIndicator>();
            
            try
            {
                LogMessage($"ET RULES: Extracting {source} tar.gz archive");
                
                using (var memoryStream = new MemoryStream(archiveData))
                using (var gzipStream = new GZipStream(memoryStream, CompressionMode.Decompress))
                {
                    LogMessage("ET RULES: Decompressing gzip layer...");
                    
                    using (var decompressedStream = new MemoryStream())
                    {
                        await gzipStream.CopyToAsync(decompressedStream);
                        var decompressedData = decompressedStream.ToArray();
                        
                        LogMessage($"ET RULES: Decompressed {decompressedData.Length} bytes from gzip");
                        
                        // Parse as text content - tar format is complex, but many tar.gz files
                        // can be read as concatenated text when dealing with rule files
                        var content = System.Text.Encoding.UTF8.GetString(decompressedData);
                        
                        // Split into potential rule sections and parse each
                        var ruleLines = content.Split('\n').Where(line => 
                            line.Trim().StartsWith("alert") || 
                            line.Trim().StartsWith("drop") || 
                            line.Trim().StartsWith("reject")).ToList();
                        
                        if (ruleLines.Count > 0)
                        {
                            LogMessage($"ET RULES: Found {ruleLines.Count} rule lines in {source} archive");
                            var combinedContent = string.Join("\n", ruleLines);
                            indicators = ParseRulesContent(combinedContent, "All", source);
                        }
                        else
                        {
                            LogMessage($"ET RULES: No recognizable Snort rules found in {source} archive");
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogMessage($"ET RULES ERROR: Failed to extract {source} archive: {ex.Message}");
            }
            
            return indicators;
        }

        private List<ETDomainIndicator> ParseRulesContent(string rulesContent, string category, string source)
        {
            var indicators = new List<ETDomainIndicator>();
            
            try
            {
                // Handle line continuations and disabled rules
                var processedContent = PreprocessRulesContent(rulesContent);
                var lines = processedContent.Split('\n');
                
                // CORRECTED APPROACH: ONLY extract from actual matching buffers
                // 
                // CRITICAL INSIGHT: Previous logic was extracting from ANY content pattern,
                // including reference URLs and payload markers. This caused massive false positives.
                //
                // NEW APPROACH: Extract ONLY from network-level matching buffers:
                // 1. dns.query (DNS lookups)
                // 2. tls.sni (HTTPS SNI)  
                // 3. http.host (HTTP Host header)
                // 4. Host|3A| (Snort Host header anchoring)
                //
                // IGNORE: reference:url, general content patterns, payload markers

                foreach (var line in lines)
                {
                    if (line.StartsWith("#") || string.IsNullOrWhiteSpace(line))
                        continue;

                    // Skip rules with negative matches - these are "must not be present" assertions
                    if (HasNegativeMatches(line))
                        continue;

                    // CRITICAL FIX: Skip rules that detect legitimate service usage/connectivity
                    if (IsLegitimateServiceUsageRule(line))
                        continue;

                    // ONLY EXTRACT FROM ACTUAL NETWORK MATCHING BUFFERS
                    
                    // 1. DNS Query Buffer (Highest Confidence)
                    indicators.AddRange(ExtractFromDnsQueryBuffer(line, category, source));
                    
                    // 2. TLS SNI Buffer (High Confidence) 
                    indicators.AddRange(ExtractFromTlsSniBuffer(line, category, source));
                    
                    // 3. HTTP Host Buffer (High Confidence)
                    indicators.AddRange(ExtractFromHttpHostBuffer(line, category, source));
                    
                    // 4. Snort Host Header Anchoring (High Confidence)
                    indicators.AddRange(ExtractFromSnortHostAnchor(line, category, source));
                    
                    // 5. DNS Hex Pattern Fallback (for rules without explicit dns.query)
                    indicators.AddRange(ExtractFromDnsHexPatterns(line, category, source));
                    
                    // 6. PCRE Capture Groups (Host/SNI anchored patterns)
                    indicators.AddRange(ExtractFromPcrePatterns(line, category, source));
                    
                    // 7. Absolute URI Patterns (strict scheme+authority gating)
                    indicators.AddRange(ExtractFromAbsoluteUriPatterns(line, category, source));
                }
                
                LogMessage($"ET RULES: Extracted {indicators.Count} domains from network matching buffers in {category} (excluding reference/payload patterns)");
                
                // CRITICAL POST-EXTRACTION FILTERING (Structural-first decision logic)
                indicators = ApplyPostExtractionFiltering(indicators);
                
                LogMessage($"ET RULES: After post-extraction filtering: {indicators.Count} legitimate IOCs remaining");

                var beforeDedupe = indicators.Count;
                indicators = DeduplicateIndicators(indicators);
                if (beforeDedupe != indicators.Count)
                {
                    LogMessage($"ET RULES: Deduped Domain+RuleId indicators: {beforeDedupe} -> {indicators.Count} (collapsed {beforeDedupe - indicators.Count})");
                }
            }
            catch (Exception ex)
            {
                LogMessage($"ET RULES ERROR: Parsing failed for {category}: {ex.Message}");
            }

            return indicators;
        }

        private List<ETDomainIndicator> DeduplicateIndicators(List<ETDomainIndicator> indicators)
        {
            if (indicators == null || indicators.Count == 0)
                return indicators ?? new List<ETDomainIndicator>();

            var bestByKey = new Dictionary<string, ETDomainIndicator>(StringComparer.OrdinalIgnoreCase);

            foreach (var indicator in indicators)
            {
                if (indicator == null || string.IsNullOrEmpty(indicator.Domain))
                    continue;

                var key = BuildDomainRuleKey(indicator.Domain, indicator.RuleId);
                if (!bestByKey.TryGetValue(key, out var existing))
                {
                    bestByKey[key] = indicator;
                    continue;
                }

                if (CompareIndicatorPreference(indicator, existing) > 0)
                {
                    bestByKey[key] = indicator;
                }
            }

            return bestByKey.Values.ToList();
        }

        private static string BuildDomainRuleKey(string domain, int ruleId)
        {
            return (domain ?? string.Empty).Trim().ToLowerInvariant() + "|" + ruleId;
        }

        private static int CompareIndicatorPreference(ETDomainIndicator candidate, ETDomainIndicator current)
        {
            var confidenceDiff = ConfidenceRank(candidate.Confidence) - ConfidenceRank(current.Confidence);
            if (confidenceDiff != 0)
                return confidenceDiff;

            return SeverityRank(candidate.Severity) - SeverityRank(current.Severity);
        }

        private static int ConfidenceRank(string confidence)
        {
            if (string.IsNullOrEmpty(confidence))
                return 0;

            switch (confidence.Trim().ToLowerInvariant())
            {
                case "high": return 3;
                case "medium": return 2;
                case "low": return 1;
                default: return 0;
            }
        }

        private static int SeverityRank(string severity)
        {
            if (string.IsNullOrEmpty(severity))
                return 0;

            switch (severity.Trim().ToLowerInvariant())
            {
                case "high": return 3;
                case "medium": return 2;
                case "low": return 1;
                default: return 0;
            }
        }

        private List<ETDomainIndicator> ExtractFromDnsQueryBuffer(string ruleLine, string category, string source)
        {
            var indicators = new List<ETDomainIndicator>();
            
            // ONLY extract if the rule explicitly uses dns.query buffer
            // This ensures we're getting actual DNS lookup domains, not payload markers
            
            if (!ruleLine.Contains("dns.query"))
                return indicators;
            
            // Pattern 1: dns.query with hex-encoded DNS labels |03|www|07|example|03|com|00|
            var dnsHexPattern = @"dns\.query[^;]*;\s*content:\s*""([^""]*(?:\|[0-9a-fA-F]{2}\|[a-zA-Z0-9-]+)+\|00\|[^""]*)""\s*;";
            var hexMatches = Regex.Matches(ruleLine, dnsHexPattern, RegexOptions.IgnoreCase);
            
            foreach (Match match in hexMatches)
            {
                var hexContent = match.Groups[1].Value;
                var domain = DecodeDnsLabels(hexContent);
                if (!string.IsNullOrEmpty(domain) && IsValidDomain(domain))
                {
                    var indicator = ParseRuleToIndicator(ruleLine, domain, category, source);
                    if (indicator != null)
                    {
                        indicator.ExtractionMethod = "dns.query-hex";
                        indicator.Confidence = "High";
                        indicators.Add(indicator);
                    }
                }
            }
            
            // Pattern 2: dns.query with ASCII domain content (CRITICAL for log4j canary domains etc.)
            var dnsDomainPattern = @"dns\.query[^;]*;\s*content:\s*""([a-zA-Z0-9._-]+\.[a-zA-Z]{2,})""\s*;";
            var domainMatches = Regex.Matches(ruleLine, dnsDomainPattern, RegexOptions.IgnoreCase);
            
            foreach (Match match in domainMatches)
            {
                var domain = match.Groups[1].Value.ToLower().Trim();
                
                // Normalize: remove trailing dot, handle IDN
                domain = NormalizeDomain(domain);
                
                if (IsValidDomain(domain))
                {
                    var indicator = ParseRuleToIndicator(ruleLine, domain, category, source);
                    if (indicator != null)
                    {
                        indicator.ExtractionMethod = "dns.query-ascii";
                        indicator.Confidence = "High";
                        indicators.Add(indicator);
                    }
                }
            }
            
            return indicators;
        }

        private List<ETDomainIndicator> ExtractFromTlsSniBuffer(string ruleLine, string category, string source)
        {
            var indicators = new List<ETDomainIndicator>();
            
            // ONLY extract if the rule explicitly uses tls.sni buffer (Suricata)
            if (ruleLine.Contains("tls.sni"))
            {
                var tlsSniPattern = @"tls\.sni[^;]*;\s*content:\s*""([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})""\s*;";
                var matches = Regex.Matches(ruleLine, tlsSniPattern, RegexOptions.IgnoreCase);
                
                foreach (Match match in matches)
                {
                    var domain = match.Groups[1].Value.ToLower().Trim();
                    if (IsValidDomain(domain))
                    {
                        var indicator = ParseRuleToIndicator(ruleLine, domain, category, source);
                        if (indicator != null)
                        {
                            indicator.ExtractionMethod = "tls.sni";
                            indicator.Confidence = "High";
                            indicators.Add(indicator);
                        }
                    }
                }
            }
            
            return indicators;
        }

        private List<ETDomainIndicator> ExtractFromHttpHostBuffer(string ruleLine, string category, string source)
        {
            var indicators = new List<ETDomainIndicator>();
            
            // ONLY extract if the rule explicitly uses http.host buffer (Suricata)
            if (ruleLine.Contains("http.host"))
            {
                var httpHostPattern = @"http\.host[^;]*;\s*content:\s*""([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})""\s*;";
                var matches = Regex.Matches(ruleLine, httpHostPattern, RegexOptions.IgnoreCase);
                
                foreach (Match match in matches)
                {
                    var domain = match.Groups[1].Value.ToLower().Trim();
                    if (IsValidDomain(domain))
                    {
                        var indicator = ParseRuleToIndicator(ruleLine, domain, category, source);
                        if (indicator != null)
                        {
                            indicator.ExtractionMethod = "http.host";
                            indicator.Confidence = "High";
                            indicators.Add(indicator);
                        }
                    }
                }
            }
            
            // ONLY extract if the rule uses Snort 3 http_header:field host
            if (ruleLine.Contains("http_header:field host"))
            {
                var snortHostPattern = @"http_header:field\s+host[^;]*;\s*content:\s*""([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})""\s*;";
                var matches = Regex.Matches(ruleLine, snortHostPattern, RegexOptions.IgnoreCase);
                
                foreach (Match match in matches)
                {
                    var domain = match.Groups[1].Value.ToLower().Trim();
                    if (IsValidDomain(domain))
                    {
                        var indicator = ParseRuleToIndicator(ruleLine, domain, category, source);
                        if (indicator != null)
                        {
                            indicator.ExtractionMethod = "http_header:field-host";
                            indicator.Confidence = "High";
                            indicators.Add(indicator);
                        }
                    }
                }
            }
            
            return indicators;
        }

        private List<ETDomainIndicator> ExtractFromSnortHostAnchor(string ruleLine, string category, string source)
        {
            var indicators = new List<ETDomainIndicator>();
            
            // IMPROVED: Block-aware Host header pairing with distance/within logic
            if (ruleLine.Contains("http_header") && ruleLine.Contains("Host|3A|"))
            {
                // Pattern 1: Direct Host|3A| followed by domain
                var directHostPattern = @"Host\|3A\|\s*([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})";
                var directMatches = Regex.Matches(ruleLine, directHostPattern, RegexOptions.IgnoreCase);
                
                foreach (Match match in directMatches)
                {
                    var domain = match.Groups[1].Value.ToLower().Trim();
                    if (IsValidDomain(domain))
                    {
                        var indicator = ParseRuleToIndicator(ruleLine, domain, category, source);
                        if (indicator != null)
                        {
                            indicator.ExtractionMethod = "Host-anchor-direct";
                            indicator.Confidence = "High";
                            indicators.Add(indicator);
                        }
                    }
                }
                
                // Pattern 2: Host|3A| anchor followed by content with distance/within
                // Example: http_header; content:"Host|3A|"; nocase; content:"evil.example"; distance:0; within:100;
                if (!directMatches.Cast<Match>().Any()) // Only if direct pattern didn't match
                {
                    indicators.AddRange(ExtractFromHostHeaderBlock(ruleLine, category, source));
                }
            }
            
            return indicators;
        }

        private List<ETDomainIndicator> ExtractFromHostHeaderBlock(string ruleLine, string category, string source)
        {
            var indicators = new List<ETDomainIndicator>();
            
            // Parse Snort rule options with sticky buffer state tracking
            var options = ParseSnortOptions(ruleLine);
            var activeBuffer = "";
            bool foundHostAnchor = false;
            
            for (int i = 0; i < options.Count; i++)
            {
                var option = options[i].Trim();
                
                // Track sticky buffer state changes
                if (IsBufferDirective(option))
                {
                    activeBuffer = GetBufferType(option);
                    foundHostAnchor = false; // Reset anchor state on buffer change
                }
                else if (activeBuffer == "http_header" && option.Contains("Host|3A|"))
                {
                    foundHostAnchor = true;
                }
                else if (activeBuffer == "http_header" && foundHostAnchor && option.StartsWith("content:"))
                {
                    // Extract domain only if we're in correct buffer with Host anchor
                    var domainPattern = @"content:\s*""([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})""\s*;?";
                    var match = Regex.Match(option, domainPattern, RegexOptions.IgnoreCase);
                    
                    if (match.Success)
                    {
                        var domain = match.Groups[1].Value.ToLower().Trim();
                        if (IsValidDomain(domain))
                        {
                            var indicator = ParseRuleToIndicator(ruleLine, domain, category, source);
                            if (indicator != null)
                            {
                                indicator.ExtractionMethod = "Host-anchor-block-tracked";
                                indicator.Confidence = "High";
                                indicators.Add(indicator);
                            }
                        }
                        break; // Found paired domain, stop looking
                    }
                }
            }
            
            return indicators;
        }

        private bool IsBufferDirective(string option)
        {
            var bufferDirectives = new[]
            {
                "http_header", "http_uri", "http_client_body", "http_server_body",
                "http_method", "http_stat_code", "http_stat_msg", "http_raw_uri",
                "file_data", "pkt_data", "base64_data", "dce_opnum", "dce_stub_data",
                "http_header:field", "ssl_state", "dns_query"
            };
            
            return bufferDirectives.Any(directive => 
                option.ToLower().StartsWith(directive.ToLower()));
        }

        private string GetBufferType(string option)
        {
            var lowerOption = option.ToLower();
            
            if (lowerOption.StartsWith("http_header:field host"))
                return "http_header_host";
            else if (lowerOption.StartsWith("http_header"))
                return "http_header";
            else if (lowerOption.StartsWith("http_uri"))
                return "http_uri";
            else if (lowerOption.StartsWith("file_data"))
                return "file_data";
            else if (lowerOption.StartsWith("dns_query"))
                return "dns_query";
            else if (lowerOption.StartsWith("ssl_state"))
                return "ssl_state";
            
            return "unknown";
        }

        private List<string> ParseSnortOptions(string ruleLine)
        {
            var options = new List<string>();
            
            // Find the options part after the rule header
            var optionsStart = ruleLine.IndexOf('(');
            var optionsEnd = ruleLine.LastIndexOf(')');
            
            if (optionsStart >= 0 && optionsEnd > optionsStart)
            {
                var optionsString = ruleLine.Substring(optionsStart + 1, optionsEnd - optionsStart - 1);
                
                // Split by semicolon but be aware of quoted strings
                var parts = new List<string>();
                bool inQuotes = false;
                var current = new StringBuilder();
                
                for (int i = 0; i < optionsString.Length; i++)
                {
                    char c = optionsString[i];
                    
                    if (c == '"' && (i == 0 || optionsString[i - 1] != '\\'))
                    {
                        inQuotes = !inQuotes;
                        current.Append(c);
                    }
                    else if (c == ';' && !inQuotes)
                    {
                        if (current.Length > 0)
                        {
                            parts.Add(current.ToString().Trim());
                            current.Clear();
                        }
                    }
                    else
                    {
                        current.Append(c);
                    }
                }
                
                if (current.Length > 0)
                {
                    parts.Add(current.ToString().Trim());
                }
                
                options = parts;
            }
            
            return options;
        }

        private List<ETDomainIndicator> ExtractFromDnsHexPatterns(string ruleLine, string category, string source)
        {
            var indicators = new List<ETDomainIndicator>();
            
            // STRICT GATING: Only process if both context AND shape gates pass
            // This prevents treating punctuation (|2e| = dot) as DNS label lengths
            
            // Gate 1: Must be DNS-related context
            if (!IsDnsContext(ruleLine))
                return indicators;
            
            // Look for hex-encoded patterns in content
            var hexPattern = @"content:\s*""([^""]*\|[0-9a-fA-F]{2}\|[^""]*)""\s*;";
            var matches = Regex.Matches(ruleLine, hexPattern, RegexOptions.IgnoreCase);
            
            foreach (Match match in matches)
            {
                var hexContent = match.Groups[1].Value;
                
                // Gate 2: Must look like a DNS QNAME (shape validation)
                if (!LooksLikeDnsQname(hexContent))
                    continue; // Skip non-DNS hex patterns (like |2e| for dots)
                
                // Extract just the QNAME portion (ignore trailing QTYPE/QCLASS)
                var qnameOnly = ExtractQnamePortionOnly(hexContent);
                
                // Strict decode with fail-fast
                var domain = DecodeDnsLabelsStrict(qnameOnly);
                if (!string.IsNullOrEmpty(domain))
                {
                    var indicator = ParseRuleToIndicator(ruleLine, domain, category, source);
                    if (indicator != null)
                    {
                        indicator.ExtractionMethod = "dns-hex-qname"; // Validated, not fallback
                        indicator.Confidence = "High";
                        indicators.Add(indicator);
                    }
                }
            }
            
            return indicators;
        }

        // CRITICAL: Strict DNS QNAME shape detection (allows trailing QTYPE/QCLASS bytes)
        private static readonly Regex QnamePipePattern = new Regex(
            @"^((?:\|[0-3][0-9A-Fa-f]\|[A-Za-z0-9-_]{1,63}){2,}\|00\|)(?:\|[0-9A-Fa-f]{2}\|)*.*?$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);
            
        private static readonly Regex QnameXPattern = new Regex(
            @"^((?:\\x[0-3][0-9A-Fa-f][A-Za-z0-9-_]{1,63}){2,}\\x00)(?:\\x[0-9A-Fa-f]{2})*.*?$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);
            
        private bool LooksLikeDnsQname(string content)
        {
            if (string.IsNullOrEmpty(content))
                return false;
                
            // Must match DNS QNAME structure: length-prefixed labels ending with 00 (may have trailing QTYPE/QCLASS)
            return QnamePipePattern.IsMatch(content) || QnameXPattern.IsMatch(content);
        }
        
        private string ExtractQnamePortionOnly(string content)
        {
            // Extract just the QNAME portion (up to and including |00|), ignoring trailing QTYPE/QCLASS
            var pipeMatch = QnamePipePattern.Match(content);
            if (pipeMatch.Success)
                return pipeMatch.Groups[1].Value; // Just the QNAME part
                
            var xMatch = QnameXPattern.Match(content);
            if (xMatch.Success)
                return xMatch.Groups[1].Value; // Just the QNAME part
                
            return content; // Fallback to original
        }
        
        private bool IsDnsContext(string ruleLine)
        {
            var lowerRule = ruleLine.ToLower();
            
            // STRONG indicators (any 1 qualifies)
            bool strong = lowerRule.Contains("dns_query") ||
                         lowerRule.Contains("dns query") ||
                         lowerRule.Contains("dns lookup") ||
                         lowerRule.Contains("$dns_ports") ||
                         (lowerRule.Contains("udp") && lowerRule.Contains("53")) ||
                         (lowerRule.Contains("proto") && lowerRule.Contains("udp") && lowerRule.Contains("dport") && lowerRule.Contains("53"));
            
            if (strong) return true;
            
            // WEAK indicators (need 2+ to qualify)
            int weak = 0;
            if (lowerRule.Contains("classtype:dns")) weak++;
            if (lowerRule.Contains("dns")) weak++;
            if (lowerRule.Contains("reference") && lowerRule.Contains("dns")) weak++;
            
            return weak >= 2;
        }
        
        private string DecodeDnsLabelsStrict(string hexContent)
        {
            // Fail-fast DNS decoder that aborts on first inconsistency
            try
            {
                var parts = new List<string>();
                var matches = Regex.Matches(hexContent, @"\|([0-9A-Fa-f]{2})\|([^|]*)", RegexOptions.IgnoreCase);
                
                for (int i = 0; i < matches.Count; i++)
                {
                    var match = matches[i];
                    var lengthHex = match.Groups[1].Value;
                    var labelContent = match.Groups[2].Value;
                    
                    // Parse length byte
                    if (!int.TryParse(lengthHex, System.Globalization.NumberStyles.HexNumber, null, out int expectedLength))
                        return null;
                    
                // CRITICAL: Fail fast on invalid length bytes (punctuation like |2e| = 46)
                if (expectedLength > 63 || expectedLength == 0)
                {
                    // Check if this is the terminator (|00|)
                    if (expectedLength == 0 && i == matches.Count - 1)
                        break; // Valid terminator
                    return null; // Invalid length - fail fast and quiet
                }
                
                // Validate label content length
                if (labelContent.Length != expectedLength)
                    return null; // Length mismatch - fail fast and quiet
                    
                    // Validate label content (alphanumeric + hyphens + underscores for SRV records, not starting/ending with hyphen)
                    if (!Regex.IsMatch(labelContent, @"^[a-zA-Z0-9_]([a-zA-Z0-9_-]*[a-zA-Z0-9_])?$"))
                        return null; // Invalid label format
                    
                    parts.Add(labelContent);
                }
                
                // Must have at least 2 parts to be a valid domain
                if (parts.Count < 2)
                    return null;
                
                var domain = string.Join(".", parts).ToLowerInvariant();
                return IsValidDomain(domain) ? domain : null;
            }
            catch
            {
                return null; // Any error = not a valid DNS QNAME
            }
        }

        private bool IsDnsRelatedRule(string ruleLine)
        {
            var lowerRule = ruleLine.ToLower();
            
            // IMPROVED: DNS detection not limited to "any 53"
            var dnsIndicators = new[]
            {
                // Port indicators (various forms)
                "53 \\(",           // Port 53 anywhere
                "\\$dns_ports",     // Variable reference
                "-> any 53",        // Traffic to DNS port
                "any -> any 53",    // DNS traffic
                "udp.*53",          // UDP DNS
                "tcp.*53",          // TCP DNS
                
                // DNS structural patterns
                "offset:2.*depth:1", // DNS header structure
                "|01|.*|00 01 00 00 00 00 00|", // DNS query pattern
                "dsize:.*offset:2", // DNS packet size + header offset
                
                // DNS content descriptions
                "dns lookup",       // DNS-related description
                "domain in dns",    // Domain DNS lookup
                "dns query",        // DNS query description
                
                // ET categories
                "et dns",           // ET DNS category
                "et info.*dns",     // ET INFO DNS
                "et activex.*dns"   // ET ACTIVEX DNS
            };
            
            // Check for any DNS indicator
            var hasDnsIndicator = dnsIndicators.Any(indicator => 
                Regex.IsMatch(lowerRule, indicator));
            
            // Additional structural validation - if hex pattern present, validate it looks like DNS labels
            if (hasDnsIndicator && lowerRule.Contains("|") && lowerRule.Contains("|00|"))
            {
                return true;
            }
            
            return hasDnsIndicator;
        }

        private bool HasNegativeMatches(string ruleLine)
        {
            // Check for negative assertions with domain patterns
            // These are "must not be present" conditions, not IOCs to extract
            
            var negativePatterns = new[]
            {
                @"!content:\s*""[^""]*[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^""]*""",  // !content:"domain.com"
                @"!pcre:\s*""[^""]*[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^""]*""",     // !pcre:"/domain\.com/"
                @"!http\.host[^;]*;\s*content:\s*""[^""]*[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^""]*""", // !http.host with domain
                @"!dns\.query[^;]*;\s*content:\s*""[^""]*[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^""]*""", // !dns.query with domain
                @"!tls\.sni[^;]*;\s*content:\s*""[^""]*[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}[^""]*"""    // !tls.sni with domain
            };
            
            foreach (var pattern in negativePatterns)
            {
                if (Regex.IsMatch(ruleLine, pattern, RegexOptions.IgnoreCase))
                {
                    LogMessage($"NEGATIVE MATCH: Skipping rule with negative domain assertion");
                    return true;
                }
            }
            
            return false;
        }

        private bool IsLegitimateServiceUsageRule(string ruleLine)
        {
            // MUCH MORE TARGETED: Only skip the most obvious non-IOC rules
            var lowerRule = ruleLine.ToLower();
            
            // ONLY skip very specific patterns that are clearly not IOCs
            
            // 1. SPECIFIC connectivity rules (much more targeted)
            if (lowerRule.Contains("likely connectivity check") || 
                lowerRule.Contains("terse unencrypted request"))
            {
                LogMessage($"CONNECTIVITY: Skipping connectivity rule");
                return true;
            }
            
            // 2. SPECIFIC User-Agent detection rules (not domain-based)
            if (lowerRule.Contains("user-agent") && 
                (lowerRule.Contains("fake") || lowerRule.Contains("suspicious user-agent") || lowerRule.Contains("malicious user-agent")))
            {
                // LogMessage($"USER-AGENT: Skipping user-agent detection rule"); // Reduced noise
                return true;
            }
            
            // 3. SPECIFIC chat/IM protocol rules (not domain IOCs)
            if ((lowerRule.Contains("jabber") || lowerRule.Contains("xmpp")) && 
                lowerRule.Contains("protocol"))
            {
                LogMessage($"PROTOCOL: Skipping IM protocol rule");
                return true;
            }
            
            // That's it! Much more conservative filtering
            return false;
        }

        // Removed overly broad ContainsLegitimateServiceInHeader - was causing too many false positives

        private List<string> ExtractFullHostFromPattern(string pcrePattern, string ruleLine)
        {
            var domains = new List<string>();
            
            try
            {
                // CRITICAL: Extract the full Host pattern for combosquat detection (SID 2023092 fix)
                // Pattern: ^Host\x3a[^\r\n]+drive\.google\.com[^\r\n]{20,}\r\n
                // This matches: Host: drive.google.com-login.secure-docs.xyz
                // NOT just: drive.google.com
                
                // Look for Host header patterns with brand domains + extra chars
                var hostBrandPattern = @"\\bHost\\s*[^\\]+([a-zA-Z0-9.-]+\\.[a-zA-Z]{2,})[^\\]*\{(\d+),\}";
                var brandMatch = Regex.Match(pcrePattern, hostBrandPattern);
                
                if (brandMatch.Success)
                {
                    var brandDomain = brandMatch.Groups[1].Value.Replace("\\.", ".");
                    var minExtraChars = int.Parse(brandMatch.Groups[2].Value);
                    
                    LogMessage($"PHISHING PATTERN: Host pattern requires {minExtraChars}+ chars after {brandDomain}");
                    
                    // For rules like SID 2023092, this indicates combosquat detection
                    // We should NOT extract the brand domain itself
                    // Instead, wait for actual traffic to provide the full combosquat domain
                    
                    // Mark this as a "template" that we'll match against traffic later
                    return new List<string>(); // Don't pre-populate with brand domain
                }
                
                // Fallback: Extract any literal domains from the pattern
                var domainPattern = @"([a-zA-Z0-9-]+(?:\\\.|\\.)[a-zA-Z0-9.-]+\\?\.[a-zA-Z]{2,})";
                var domainMatches = Regex.Matches(pcrePattern, domainPattern);
                
                foreach (Match match in domainMatches)
                {
                    var domain = match.Groups[1].Value.Replace("\\.", ".");
                    
                    // Skip if this appears to be a brand anchor (part of combosquat detection)
                    if (IsWellKnownBrand(domain))
                    {
                        LogMessage($"BRAND ANCHOR: Skipping {domain} (appears to be combosquat detection anchor)");
                        continue;
                    }
                    
                    domains.Add(domain);
                }
            }
            catch (Exception ex)
            {
                LogMessage($"HOST PATTERN ERROR: {ex.Message}");
            }
            
            return domains;
        }

        private bool IsWellKnownBrand(string domain)
        {
            var wellKnownBrands = new[]
            {
                // Google ecosystem (COMPREHENSIVE - most common in ET false positives)
                "google.com", "drive.google.com", "docs.google.com", "gmail.com",
                "googleapis.com", "gstatic.com", "googlevideo.com", "googleusercontent.com",
                "goog", "youtube.com", "ytimg.com", "googlesyndication.com", "googletagmanager.com",
                "googleadservices.com", "googleblog.com", "ggpht.com", "googlecode.com",
                "sites.google.com", "maps.google.com", "translate.google.com",
                
                // Microsoft ecosystem  
                "microsoft.com", "office.com", "outlook.com", "live.com",
                "msn.com", "bing.com", "microsoftonline.com", "office365.com",
                "skype.com", "xbox.com", "windows.com",
                
                // Social media and major platforms
                "facebook.com", "instagram.com", "twitter.com", "linkedin.com",
                "youtube.com", "tiktok.com", "reddit.com", "snapchat.com",
                
                // Cloud and services
                "dropbox.com", "icloud.com", "yahoo.com", "amazon.com", "apple.com",
                "onedrive.com", "sharepoint.com", "paypal.com", "ebay.com",
                "aws.amazon.com", "zoom.us", "salesforce.com", "adobe.com"
            };
            
            var normalizedDomain = domain.ToLower().Trim();
            return wellKnownBrands.Contains(normalizedDomain);
        }

        private List<ETDomainIndicator> ApplyPostExtractionFiltering(List<ETDomainIndicator> indicators)
        {
            var filteredIndicators = new List<ETDomainIndicator>();
            
            foreach (var indicator in indicators)
            {
                // KILL FALLBACK EMISSIONS: Don't emit indicators from fallback methods
                if (indicator.ExtractionMethod?.EndsWith("fallback", StringComparison.OrdinalIgnoreCase) == true)
                {
                    continue; // Drop silently - fallback methods are too noisy
                }
                
                var decision = MakePostExtractionDecision(indicator);
                
                if (decision.ShouldInclude)
                {
                    // Apply any modifications from the decision
                    if (!string.IsNullOrEmpty(decision.ModifiedDomain))
                    {
                        indicator.Domain = decision.ModifiedDomain;
                    }
                    
                    filteredIndicators.Add(indicator);
                }
                else
                {
                    LogMessage($"POST-FILTER REJECT: {indicator.Domain} from SID {indicator.RuleId} - {decision.Reason}");
                }
            }
            
            return filteredIndicators;
        }

        private PostExtractionDecision MakePostExtractionDecision(ETDomainIndicator indicator)
        {
            var domain = indicator.Domain;
            var msg = indicator.Description?.ToLower() ?? "";
            var etld1 = ExtractETLD1(domain);
            
            // STRUCTURAL VALIDATION: Must be from legitimate network buffers
            var validExtractionMethods = new[] { 
                "dns-query", "dns-hex-qname", "dns.query-ascii",
                "tls-sni", "tls.sni", 
                "http-host", "http.host", "host-header",
                "pcre-host", "uri-absolute"
            };
            var extractionMethod = indicator.ExtractionMethod?.ToLower() ?? "";
            
            if (!validExtractionMethods.Contains(extractionMethod))
            {
                return new PostExtractionDecision(false, $"Invalid extraction method: {indicator.ExtractionMethod}");
            }
            
            // STRUCTURAL-FIRST DECISION LOGIC: Fix the precise cases that leaked
            
            // 1. SID 2036303 FIX: google.com from connectivity/terse unencrypted rules
            //    These are behavioral indicators, not IOCs
            if (msg.Contains("terse") && msg.Contains("unencrypted") ||
                msg.Contains("likely connectivity") ||
                msg.Contains("connectivity check") ||
                msg.Contains("sid:2036303"))
            {
                LogMessage($"SID 2036303 FILTERED: Rejected domain {domain} from connectivity rule");
                return new PostExtractionDecision(false, $"Behavioral/connectivity rule - not IOC: {domain}");
            }
            
            // 2. SID 2023092 & CURRENT_EVENTS phishing detection rules
            //    These look for "brand + extra chars" - if we got the brand itself, that's wrong
            if ((msg.Contains("current_events") || msg.Contains("sid:2023092")) && 
                msg.Contains("phishing"))
            {
                if (IsWellKnownBrand(etld1))
                {
                    LogMessage($"SID 2023092 FILTERED: Rejected brand domain {domain} (eTLD+1={etld1}) from phishing detection rule");
                    return new PostExtractionDecision(false, $"Brand eTLD+1 {etld1} from phishing detection rule - should be combosquat");
                }
                // If eTLD+1 is NOT a brand, keep it (it's the combosquat we want)
                LogMessage($"SID 2023092 ACCEPTED: Non-brand domain {domain} (eTLD+1={etld1}) from phishing detection rule - likely combosquat");
            }
            
            // 3. Cobalt Strike Malleable C2 decoy hosts
            if (msg.Contains("malleable c2") && IsWellKnownBrand(etld1))
            {
                return new PostExtractionDecision(false, $"Malleable C2 decoy host {domain} - behavioral, not IOC");
            }
            
            // 4. Excessive DNS responses and other generic heuristics
            if ((msg.Contains("excessive dns responses") || 
                 msg.Contains("fake googlebot") ||
                 msg.Contains("fake user-agent")) && IsWellKnownBrand(etld1))
            {
                return new PostExtractionDecision(false, $"Generic heuristic with brand domain {domain} - not IOC");
            }
            
            // 5. Brand domains: Only accept if explicitly flagged as malicious lookalike
            if (IsWellKnownBrand(etld1))
            {
                // Accept brand domains ONLY if rule explicitly flags them as malicious
                if (msg.Contains("fake") && !msg.Contains("fake googlebot") ||
                    msg.Contains("malicious") ||
                    msg.Contains("lookalike") ||
                    msg.Contains("typosquat") ||
                    msg.Contains("combosquat"))
                {
                    return new PostExtractionDecision(true, $"Explicit malicious lookalike: {domain}");
                }
                
                // Default: reject brand domains unless explicitly malicious
                return new PostExtractionDecision(false, $"Brand domain {etld1} without explicit malicious context");
            }
            
            // 5. Default: accept non-brand domains from valid buffers
            return new PostExtractionDecision(true);
        }

        private string ExtractETLD1(string domain)
        {
            // Simple eTLD+1 extraction (registrable domain)
            try
            {
                var parts = domain.ToLower().Split('.');
                if (parts.Length >= 2)
                {
                    // For most cases, take last two parts (SLD.TLD)
                    return $"{parts[parts.Length - 2]}.{parts[parts.Length - 1]}";
                }
                return domain;
            }
            catch
            {
                return domain;
            }
        }

        private string PreprocessRulesContent(string rulesContent)
        {
            try
            {
                var lines = rulesContent.Split(new[] { '\n', '\r' }, StringSplitOptions.None);
                var processedLines = new List<string>();
                
                for (int i = 0; i < lines.Length; i++)
                {
                    var line = lines[i].Trim();
                    
                    // Skip empty lines
                    if (string.IsNullOrWhiteSpace(line))
                        continue;
                    
                    // Skip disabled rules (starting with #)
                    if (line.StartsWith("#"))
                        continue;
                    
                    // Handle line continuations (trailing \)
                    var currentLine = line;
                    
                    // Concatenate continued lines
                    while (currentLine.EndsWith("\\") && i + 1 < lines.Length)
                    {
                        i++; // Move to next line
                        var nextLine = lines[i].Trim();
                        
                        // Remove trailing \ and append next line
                        currentLine = currentLine.TrimEnd('\\') + " " + nextLine;
                    }
                    
                    if (!string.IsNullOrWhiteSpace(currentLine))
                    {
                        processedLines.Add(currentLine);
                    }
                }
                
                return string.Join("\n", processedLines);
            }
            catch (Exception ex)
            {
                LogMessage($"PREPROCESS ERROR: {ex.Message}");
                return rulesContent; // Return original if preprocessing fails
            }
        }

        private List<ETDomainIndicator> ExtractFromPcrePatterns(string ruleLine, string category, string source)
        {
            var indicators = new List<ETDomainIndicator>();
            
            // Extract domains from PCRE patterns with capture groups
            // Focus on Host-anchored and SNI patterns
            
            if (ruleLine.Contains("pcre:"))
            {
                // Pattern 1: Host header anchored PCRE - EXTRACT FULL HOST (CRITICAL FIX for SID 2023092)
                
                // A) Explicit capture groups: pcre:"/^Host\\s*:\\s*([^\\r\\n]*example\\.com)/mi"; http_header;
                var hostPcrePattern = @"pcre:\s*""[^""]*\\bHost\\s*:\\s*\(([^)]+)\)[^""]*""\s*;[^;]*http_header";
                var hostMatches = Regex.Matches(ruleLine, hostPcrePattern, RegexOptions.IgnoreCase);
                
                foreach (Match match in hostMatches)
                {
                    var captureGroup = match.Groups[1].Value;
                    var domain = UnescapePcreAndExtractDomain(captureGroup);
                    
                    if (!string.IsNullOrEmpty(domain) && IsValidDomain(domain))
                    {
                        var indicator = ParseRuleToIndicator(ruleLine, domain, category, source);
                        if (indicator != null)
                        {
                            indicator.ExtractionMethod = "pcre-host-capture";
                            indicator.Confidence = "High";
                            indicators.Add(indicator);
                        }
                    }
                }
                
                // B) CRITICAL: Synthesize capture groups for Host patterns without explicit groups
                // Example: pcre:"/^Host\x3a[^\r\n]+drive\.google\.com[^\r\n]{20,}\r\n/Hmi" (SID 2023092)
                var hostSynthesizePattern = @"pcre:\s*""([^""]*\\bHost\\s*[^""]*\\\\[^""]+\\\\[^""]*[^""]*)""\s*;[^;]*http_header";
                var synthesizeMatches = Regex.Matches(ruleLine, hostSynthesizePattern, RegexOptions.IgnoreCase);
                
                foreach (Match synthMatch in synthesizeMatches)
                {
                    var fullPattern = synthMatch.Groups[1].Value;
                    
                    // CRITICAL: For phishing detection patterns, extract the FULL HOST pattern, not the brand substring
                    var fullHostDomains = ExtractFullHostFromPattern(fullPattern, ruleLine);
                    
                    // DIAGNOSTIC: Log when we encounter SID 2023092 specifically
                    if (ruleLine.Contains("sid:2023092"))
                    {
                        LogMessage($"SID 2023092 PCRE: Pattern={fullPattern}, Extracted domains={string.Join(",", fullHostDomains)}");
                    }
                    
                    foreach (var domain in fullHostDomains)
                    {
                        if (!string.IsNullOrEmpty(domain) && IsValidDomain(domain))
                        {
                            var indicator = ParseRuleToIndicator(ruleLine, domain, category, source);
                            if (indicator != null)
                            {
                                indicator.ExtractionMethod = "pcre-host-synthesized";
                                indicator.Confidence = "High";
                                indicators.Add(indicator);
                            }
                        }
                    }
                }
                
                // Pattern 2: TLS SNI PCRE patterns (less common in current rules but for completeness)
                var sniPcrePattern = @"pcre:\s*""[^""]*\\b(?:sni|server.*name)[^""]*\(([^)]+)\)[^""]*""\s*;";
                var sniMatches = Regex.Matches(ruleLine, sniPcrePattern, RegexOptions.IgnoreCase);
                
                foreach (Match match in sniMatches)
                {
                    var captureGroup = match.Groups[1].Value;
                    var domain = UnescapePcreAndExtractDomain(captureGroup);
                    
                    if (!string.IsNullOrEmpty(domain) && IsValidDomain(domain))
                    {
                        var indicator = ParseRuleToIndicator(ruleLine, domain, category, source);
                        if (indicator != null)
                        {
                            indicator.ExtractionMethod = "pcre-sni-capture";
                            indicator.Confidence = "Medium";
                            indicators.Add(indicator);
                        }
                    }
                }
                
                // Pattern 3: No capture group but domain patterns in PCRE (fallback)
                if (!hostMatches.Cast<Match>().Any() && !sniMatches.Cast<Match>().Any())
                {
                    indicators.AddRange(ExtractFromPcreFallback(ruleLine, category, source));
                }
            }
            
            return indicators;
        }

        private List<ETDomainIndicator> ExtractFromPcreFallback(string ruleLine, string category, string source)
        {
            var indicators = new List<ETDomainIndicator>();
            
            // Extract from PCRE patterns without explicit capture groups
            // Only if rule is in appropriate context (Host/SNI related)
            
            if (!ruleLine.ToLower().Contains("http_header") && !ruleLine.ToLower().Contains("ssl_state"))
                return indicators;
            
            var pcrePattern = @"pcre:\s*""([^""]+)""\s*;";
            var matches = Regex.Matches(ruleLine, pcrePattern, RegexOptions.IgnoreCase);
            
            foreach (Match match in matches)
            {
                var pcreContent = match.Groups[1].Value;
                var domain = UnescapePcreAndExtractDomain(pcreContent);
                
                if (!string.IsNullOrEmpty(domain) && IsValidDomain(domain))
                {
                    var indicator = ParseRuleToIndicator(ruleLine, domain, category, source);
                    if (indicator != null)
                    {
                        indicator.ExtractionMethod = "pcre-fallback";
                        indicator.Confidence = "Low";
                        indicators.Add(indicator);
                    }
                }
            }
            
            return indicators;
        }

        private string UnescapePcreAndExtractDomain(string pcreContent)
        {
            try
            {
                // ENHANCED: Support alternations and multiple capture groups
                var domains = ExtractDomainsFromPcre(pcreContent);
                
                // Return first valid domain (could be enhanced to return all)
                return domains.FirstOrDefault();
            }
            catch
            {
                return null;
            }
        }

        private List<string> ExtractDomainsFromPcre(string pcreContent)
        {
            var domains = new List<string>();
            
            try
            {
                // 1. Try to extract from capture groups first
                var captureGroups = ExtractFromCaptureGroups(pcreContent);
                domains.AddRange(captureGroups);
                
                // 2. Look for alternations: (?:evil\.com|cdn\.evil\.net)
                var alternations = ExtractFromAlternations(pcreContent);
                domains.AddRange(alternations);
                
                // 3. Fallback: unescape and scan for domain patterns
                if (domains.Count == 0)
                {
                    var fallbackDomain = UnescapeAndExtractFallback(pcreContent);
                    if (!string.IsNullOrEmpty(fallbackDomain))
                        domains.Add(fallbackDomain);
                }
                
                // Normalize and validate all domains
                return domains
                    .Select(d => NormalizeDomain(d))
                    .Where(d => !string.IsNullOrEmpty(d) && IsValidDomain(d))
                    .Distinct()
                    .ToList();
            }
            catch
            {
                return new List<string>();
            }
        }

        private List<string> ExtractFromCaptureGroups(string pcreContent)
        {
            var domains = new List<string>();
            
            // Look for capture groups with domain patterns
            var capturePattern = @"\(([^)]+)\)";
            var matches = Regex.Matches(pcreContent, capturePattern);
            
            foreach (Match match in matches)
            {
                var groupContent = match.Groups[1].Value;
                var unescaped = UnescapePcreString(groupContent);
                
                // Extract domains from the capture group
                var domainPattern = @"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})";
                var domainMatches = Regex.Matches(unescaped, domainPattern);
                
                foreach (Match domainMatch in domainMatches)
                {
                    var domain = domainMatch.Groups[1].Value.ToLower().Trim();
                    
                    // Remove port if present (example.com:8443)
                    if (domain.Contains(":"))
                        domain = domain.Split(':')[0];
                    
                    if (!string.IsNullOrEmpty(domain))
                        domains.Add(domain);
                }
            }
            
            return domains;
        }

        private List<string> ExtractFromAlternations(string pcreContent)
        {
            var domains = new List<string>();
            
            // Look for alternations: (?:domain1|domain2|domain3)
            var alternationPattern = @"\(\?\:([^)]+)\)";
            var matches = Regex.Matches(pcreContent, alternationPattern);
            
            foreach (Match match in matches)
            {
                var alternationContent = match.Groups[1].Value;
                var alternatives = alternationContent.Split('|');
                
                foreach (var alt in alternatives)
                {
                    var unescaped = UnescapePcreString(alt);
                    var domainPattern = @"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})";
                    var domainMatch = Regex.Match(unescaped, domainPattern);
                    
                    if (domainMatch.Success)
                    {
                        var domain = domainMatch.Groups[1].Value.ToLower().Trim();
                        
                        // Remove port if present
                        if (domain.Contains(":"))
                            domain = domain.Split(':')[0];
                        
                        if (!string.IsNullOrEmpty(domain))
                            domains.Add(domain);
                    }
                }
            }
            
            return domains;
        }

        private string UnescapeAndExtractFallback(string pcreContent)
        {
            var unescaped = UnescapePcreString(pcreContent);
            
            // Extract domain-like patterns
            var domainPattern = @"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})";
            var match = Regex.Match(unescaped, domainPattern);
            
            if (match.Success)
            {
                var domain = match.Groups[1].Value.ToLower().Trim();
                
                // Remove port if present
                if (domain.Contains(":"))
                    domain = domain.Split(':')[0];
                
                return domain;
            }
            
            return null;
        }

        private string UnescapePcreString(string input)
        {
            return input
                .Replace("\\\\", "\\")      // Double backslash to single
                .Replace("\\.", ".")        // Escaped dots
                .Replace("\\x2e", ".")      // Hex encoded dots
                .Replace("\\s*", "")        // Remove whitespace patterns
                .Replace("\\r", "")         // Remove carriage return
                .Replace("\\n", "")         // Remove newline
                .Replace(".*", "")          // Remove wildcard patterns
                .Replace(".+", "")          // Remove one-or-more patterns
                .Replace("\\b", "")         // Remove word boundaries
                .Replace("\\w+", "")        // Remove word patterns
                .Replace("[^\\r\\n]*", "")  // Remove character class patterns
                .Replace("[^)]+", "");      // Remove capture group patterns
        }

        private List<ETDomainIndicator> ExtractFromAbsoluteUriPatterns(string ruleLine, string category, string source)
        {
            var indicators = new List<ETDomainIndicator>();
            
            // STRICT: Only extract absolute URIs with scheme+authority from URI buffers
            if (ruleLine.Contains("http_uri") || ruleLine.Contains("http.uri") || 
                ruleLine.Contains("http.request_line") || ruleLine.Contains("uricontent"))
            {
                // Only extract when pattern includes scheme://authority (not just paths)
                var absoluteUriPattern = @"content:\s*""[^""]*https?://([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})(?:[:/][^""]*)?[^""]*""\s*;";
                var matches = Regex.Matches(ruleLine, absoluteUriPattern, RegexOptions.IgnoreCase);
                
                foreach (Match match in matches)
                {
                    var domain = match.Groups[1].Value;
                    var normalizedDomain = NormalizeDomain(domain);
                    
                    if (!string.IsNullOrEmpty(normalizedDomain) && IsValidDomain(normalizedDomain))
                    {
                        var indicator = ParseRuleToIndicator(ruleLine, normalizedDomain, category, source);
                        if (indicator != null)
                        {
                            indicator.ExtractionMethod = "absolute-uri-strict";
                            indicator.Confidence = "Medium";
                            indicators.Add(indicator);
                        }
                    }
                }
            }
            
            return indicators;
        }

        private string NormalizeDomain(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
                return null;
            
            try
            {
                // Step 1: Basic cleanup
                var normalized = domain.Trim().ToLower();
                
                // Step 2: Decode hex patterns
                normalized = DecodeHexPatterns(normalized);
                
                // Step 3: Remove trailing dot (FQDN to relative)
                if (normalized.EndsWith("."))
                    normalized = normalized.TrimEnd('.');
                
                // Step 4: Collapse multiple dots
                while (normalized.Contains(".."))
                    normalized = normalized.Replace("..", ".");
                
                // Step 5: Remove leading/trailing dots from cleanup
                normalized = normalized.Trim('.');
                
                // Step 6: Handle IDNA (keep ASCII xn-- as canonical)
                normalized = HandleIdna(normalized);
                
                // Step 7: Validate final format
                if (string.IsNullOrEmpty(normalized) || !IsValidDomainFormat(normalized))
                    return null;
                
                return normalized;
            }
            catch
            {
                return null;
            }
        }

        private string HandleIdna(string domain)
        {
            // Keep ASCII xn-- domains as canonical (Punycode)
            // This is production-ready - we store the ASCII version
            // Could add Unicode shadow field later if needed for display
            
            if (domain.Contains("xn--"))
            {
                // Validate Punycode format
                var parts = domain.Split('.');
                foreach (var part in parts)
                {
                    if (part.StartsWith("xn--") && part.Length < 6)
                    {
                        // Invalid Punycode (too short)
                        return null;
                    }
                }
            }
            
            return domain;
        }

        private string ExtractRegistrableDomain(string domain)
        {
            // Simple eTLD+1 extraction without full PSL
            // For production, consider using a proper PSL library
            
            if (string.IsNullOrEmpty(domain))
                return null;
            
            var parts = domain.Split('.');
            if (parts.Length < 2)
                return domain;
            
            // Common TLD patterns for basic eTLD+1
            var commonTlds = new[]
            {
                "com", "net", "org", "edu", "gov", "mil", "int",
                "co.uk", "com.au", "co.jp", "com.br", "co.za"
            };
            
            // Look for known multi-part TLDs
            foreach (var tld in commonTlds.Where(t => t.Contains(".")))
            {
                if (domain.EndsWith("." + tld))
                {
                    var tldParts = tld.Split('.').Length;
                    if (parts.Length > tldParts)
                    {
                        var startIndex = parts.Length - tldParts - 1;
                        return string.Join(".", parts.Skip(startIndex));
                    }
                }
            }
            
            // Default: last two parts (domain.tld)
            if (parts.Length >= 2)
            {
                return string.Join(".", parts.Skip(parts.Length - 2));
            }
            
            return domain;
        }

        private string DecodeHexPatterns(string input)
        {
            try
            {
                // Decode |hh| patterns
                var hexPattern = @"\|([0-9A-Fa-f]{2})\|";
                var decoded = Regex.Replace(input, hexPattern, match =>
                {
                    var hexValue = match.Groups[1].Value;
                    var byteValue = Convert.ToByte(hexValue, 16);
                    
                    // Convert common hex values
                    if (byteValue == 0x2E) return ".";  // Dot
                    if (byteValue == 0x3A) return ":";  // Colon
                    if (byteValue >= 32 && byteValue <= 126) // Printable ASCII
                        return ((char)byteValue).ToString();
                    
                    return ""; // Skip non-printable
                });
                
                // Decode \xhh patterns
                var backslashHexPattern = @"\\x([0-9A-Fa-f]{2})";
                decoded = Regex.Replace(decoded, backslashHexPattern, match =>
                {
                    var hexValue = match.Groups[1].Value;
                    var byteValue = Convert.ToByte(hexValue, 16);
                    
                    if (byteValue == 0x2E) return ".";
                    if (byteValue >= 32 && byteValue <= 126)
                        return ((char)byteValue).ToString();
                    
                    return "";
                });
                
                return decoded;
            }
            catch
            {
                return input;
            }
        }

        private bool IsValidDomainFormat(string domain)
        {
            if (string.IsNullOrEmpty(domain))
                return false;
            
            // Basic format validation
            if (domain.Length > 255)
                return false;
            
            if (domain.StartsWith(".") || domain.EndsWith("."))
                return false;
            
            if (domain.Contains(".."))
                return false;
            
            // Must contain at least one dot and valid TLD
            var parts = domain.Split('.');
            if (parts.Length < 2)
                return false;
            
            // Last part should be valid TLD (2+ characters)
            var tld = parts[parts.Length - 1];
            if (tld.Length < 2 || !Regex.IsMatch(tld, @"^[a-z]{2,}$"))
                return false;
            
            // All parts should be valid labels
            foreach (var part in parts)
            {
                if (string.IsNullOrEmpty(part) || part.Length > 63)
                    return false;
                
                if (!Regex.IsMatch(part, @"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$"))
                    return false;
            }
            
            return true;
        }







        private ETDomainIndicator ParseRuleToIndicator(string ruleLine, string originalDomain, string category, string source)
        {
            try
            {
                // Extract rule components
                var sidMatch = Regex.Match(ruleLine, @"sid:\s*(\d+)\s*;");
                var msgMatch = Regex.Match(ruleLine, @"msg:\s*""([^""]+)""\s*;");
                var classTypeMatch = Regex.Match(ruleLine, @"classtype:\s*([^;]+)\s*;");
                var referenceMatch = Regex.Match(ruleLine, @"reference:\s*([^;]+)\s*;");
                var createdAt = ParseEtMetadataDate(ruleLine, "created_at");
                var updatedAt = ParseEtMetadataDate(ruleLine, "updated_at");
                var now = DateTime.Now;
                var description = msgMatch.Success ? msgMatch.Groups[1].Value.Trim() : $"Unknown {category} indicator";

                return new ETDomainIndicator
                {
                    Domain = originalDomain, // Store exact malicious domain (e.g., "linkedin-phish.com")
                    MainDomain = originalDomain, // Keep same - no normalization for malicious domains
                    RuleId = sidMatch.Success ? int.Parse(sidMatch.Groups[1].Value) : 0,
                    Description = description,
                    Classification = classTypeMatch.Success ? classTypeMatch.Groups[1].Value.Trim() : category.ToLower(),
                    Severity = DetermineSeverity(ruleLine, category),
                    RuleSource = ResolveRuleSource(description, source),
                    MetadataCreatedAt = createdAt,
                    MetadataUpdatedAt = updatedAt,
                    FirstSeen = createdAt ?? now,
                    LastUpdated = updatedAt ?? now,
                    Reference = referenceMatch.Success ? referenceMatch.Groups[1].Value.Trim() : null
                };
            }
            catch (Exception ex)
            {
                LogMessage($"ET RULES ERROR: Failed to parse rule for domain {originalDomain}: {ex.Message}");
                return null;
            }
        }

        private static string ResolveRuleSource(string description, string archiveSource)
        {
            if (!string.IsNullOrEmpty(description))
            {
                if (description.StartsWith("ETPRO", StringComparison.OrdinalIgnoreCase))
                    return "ET Pro";
                if (description.StartsWith("ET ", StringComparison.OrdinalIgnoreCase))
                    return "ET Open";
            }

            return archiveSource ?? "ET Open";
        }

        private static DateTime? ParseEtMetadataDate(string ruleLine, string fieldName)
        {
            if (string.IsNullOrEmpty(ruleLine) || string.IsNullOrEmpty(fieldName))
                return null;

            var match = Regex.Match(ruleLine, fieldName + @"\s+(\d{4})_(\d{2})_(\d{2})", RegexOptions.IgnoreCase);
            if (!match.Success)
                return null;

            try
            {
                var year = int.Parse(match.Groups[1].Value, CultureInfo.InvariantCulture);
                var month = int.Parse(match.Groups[2].Value, CultureInfo.InvariantCulture);
                var day = int.Parse(match.Groups[3].Value, CultureInfo.InvariantCulture);
                return new DateTime(year, month, day, 0, 0, 0, DateTimeKind.Unspecified);
            }
            catch
            {
                return null;
            }
        }

        private string DetermineSeverity(string ruleLine, string category)
        {
            var lowerRule = ruleLine.ToLower();

            // High severity indicators
            if (lowerRule.Contains("trojan") || lowerRule.Contains("malware") || 
                lowerRule.Contains("backdoor") || lowerRule.Contains("botnet") ||
                lowerRule.Contains("exploit") || lowerRule.Contains("ransomware"))
            {
                return "high";
            }

            // Medium severity indicators  
            if (lowerRule.Contains("suspicious") || lowerRule.Contains("phishing") ||
                lowerRule.Contains("spam") || lowerRule.Contains("adware") ||
                category.Equals("DNS", StringComparison.OrdinalIgnoreCase))
            {
                return "medium";
            }

            // Default to low severity
            return "low";
        }

        private bool IsValidDomain(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain) || domain.Length < 3)
                return false;

            // Basic domain validation
            var domainPattern = @"^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]\.[a-zA-Z]{2,}$";
            return Regex.IsMatch(domain, domainPattern) && 
                   !domain.Contains("..") && 
                   !domain.StartsWith(".") && 
                   !domain.EndsWith(".");
        }

        private bool IsLegitimateServiceDetectionRule(string ruleLine)
        {
            var lowerLine = ruleLine.ToLower();
            
            // ENHANCED: Detect protocol/service detection rules more accurately
            // These rules detect legitimate service traffic, not malicious domains
            
            // Classification-based detection (most reliable)
            if (lowerLine.Contains("policy-violation") || lowerLine.Contains("not-suspicious"))
            {
                // Additional context checks for policy violations
                if (lowerLine.Contains("chat") || lowerLine.Contains("jabber") || 
                    lowerLine.Contains("talk") || lowerLine.Contains("im ") ||
                    lowerLine.Contains("streaming") || lowerLine.Contains("music") ||
                    lowerLine.Contains("voip"))
                {
                    return true;
                }
            }
            
            // Service-specific patterns (comprehensive list)
            var servicePatterns = new[]
            {
                "google talk", "jabber/google talk", "google im traffic",
                "facebook chat", "yahoo im", "msn messenger",
                "skype", "irc user command", "irc nick command",
                "ssl traffic.*being excluded", "known ssl traffic",
                "google music streaming", "google talk tls",
                "fake googlebot ua", // User agent detection, not malicious domain
                "observed google dns", // DNS monitoring, not malicious
                "possible phishing.*google", // Phishing detection, not Google as IOC
                "google drive phishing" // Phishing targeting Google, not Google as IOC
            };

            // GPL/ET markers for legitimate service detection
            var legitimateMarkers = new[]
            {
                "gpl chat", "et chat", "et policy", "et info.*google"
            };

            return servicePatterns.Any(pattern => Regex.IsMatch(lowerLine, pattern)) ||
                   legitimateMarkers.Any(marker => Regex.IsMatch(lowerLine, marker));
        }

        private bool IsKnownLegitimateReferenceSite(string domain)
        {
            // Reference URLs that point to documentation, not malicious sites
            var legitimateReferenceSites = new[]
            {
                "microsoft.com",
                "technet.microsoft.com",
                "msdn.microsoft.com",
                "cisco.com",
                "adobe.com",
                "oracle.com",
                "kb.cert.org",
                "cve.mitre.org",
                "nvd.nist.gov",
                "securityfocus.com",
                "bugtraq.com",
                "packetstormsecurity.com",
                "exploit-db.com",
                "github.com",
                "docs.microsoft.com"
            };

            return legitimateReferenceSites.Any(site => domain.Contains(site));
        }

        private bool IsMaliciousContext(string ruleLine)
        {
            var lowerLine = ruleLine.ToLower();
            
            // Indicators that this rule detects actual malicious activity
            var maliciousContexts = new[]
            {
                "trojan",
                "malware", 
                "botnet",
                "backdoor",
                "exploit",
                "attack",
                "suspicious",
                "phishing",
                "scam",
                "fraud",
                "c2",
                "command.*control",
                "shellcode",
                "ransomware",
                "adware",
                "spyware"
            };

            return maliciousContexts.Any(context => Regex.IsMatch(lowerLine, context));
        }

        private string DecodeDnsLabels(string hexContent)
        {
            try
            {
                // ENHANCED: Buffer-agnostic DNS label validation with RFC compliance
                // Decode DNS labels from hex format: |03|www|07|example|03|com|00|
                
                var parts = new List<string>();
                var hexPattern = @"\|([0-9a-fA-F]{2})\|([a-zA-Z0-9-]*?)(?=\|[0-9a-fA-F]{2}\||$)";
                var matches = Regex.Matches(hexContent, hexPattern, RegexOptions.IgnoreCase);
                
                int totalLength = 0;
                
                foreach (Match match in matches)
                {
                    var lengthHex = match.Groups[1].Value;
                    var label = match.Groups[2].Value;
                    
                    if (int.TryParse(lengthHex, System.Globalization.NumberStyles.HexNumber, null, out int length))
                    {
                        if (length == 0) break; // End of domain (root)
                        
                        // RFC 1035 validation
                        if (length > 63)
                        {
                            LogMessage($"DNS DECODE: Label too long ({length} > 63): {label}");
                            return string.Empty;
                        }
                        
                        if (label.Length != length)
                        {
                            LogMessage($"DNS DECODE: Length mismatch (expected {length}, got {label.Length}): {label}");
                            continue;
                        }
                        
                        // Validate label characters (RFC compliant)
                        if (!IsValidDnsLabel(label))
                        {
                            LogMessage($"DNS DECODE: Invalid label characters: {label}");
                            return string.Empty;
                        }
                        
                        parts.Add(label);
                        totalLength += length + 1; // +1 for length byte
                    }
                }
                
                // RFC 1035: Total domain name ≤ 255 octets
                if (totalLength > 255)
                {
                    LogMessage($"DNS DECODE: Total domain length too long ({totalLength} > 255)");
                    return string.Empty;
                }
                
                // Must have at least 2 parts for valid domain
                if (parts.Count < 2)
                {
                    LogMessage($"DNS DECODE: Insufficient domain parts ({parts.Count} < 2)");
                    return string.Empty;
                }
                
                var domain = string.Join(".", parts).ToLower();
                domain = NormalizeDomain(domain);
                
                if (IsValidDomainFormat(domain))
                    return domain;
                
                LogMessage($"DNS DECODE: Final validation failed for: {domain}");
                return string.Empty;
            }
            catch (Exception ex)
            {
                LogMessage($"DNS DECODE ERROR: {ex.Message} for content: {hexContent}");
                return string.Empty;
            }
        }

        private bool IsValidDnsLabel(string label)
        {
            if (string.IsNullOrEmpty(label))
                return false;
            
            // RFC 1035: Labels can contain letters, digits, and hyphens
            // Cannot start or end with hyphen
            if (label.StartsWith("-") || label.EndsWith("-"))
                return false;
            
            // Check all characters are valid
            foreach (char c in label)
            {
                if (!char.IsLetterOrDigit(c) && c != '-')
                    return false;
            }
            
            return true;
        }

        private bool IsKnownLegitimateService(string domain)
        {
            // Filter out known legitimate service domains that appear in protocol detection rules
            var legitimateServices = new[]
            {
                "google.com",
                "gmail.com", 
                "facebook.com",
                "chat.facebook.com",
                "yahoo.com",
                "microsoft.com",
                "live.com",
                "hotmail.com",
                "skype.com",
                "twitter.com",
                "talk.google.com",
                "www.xmpp.org",
                "www.facebook.com"
            };

            return legitimateServices.Contains(domain);
        }

        private async Task StoreDomainIndicatorsAsync(List<ETDomainIndicator> indicators, string source)
        {
            try
            {
                // Ensure initialization is complete before storing
                if (!_initializationComplete)
                {
                    LogMessage("ET RULES: Waiting for initialization to complete before storing rules");
                    return;
                }

                if (indicators == null || indicators.Count == 0)
                {
                    LogMessage("ET RULES: Store skipped - empty indicator set preserves existing rows");
                    return;
                }

                // Safety net if caller did not dedupe
                indicators = DeduplicateIndicators(indicators);

                // Load prior FirstSeen values so metadata-less rules keep local history
                var priorFirstSeen = LoadPriorFirstSeenMap();
                var now = DateTime.Now;
                var currentKeys = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                using (var transaction = _database.BeginTransaction())
                {
                    using (var createTemp = new SQLiteCommand(@"
                        CREATE TEMP TABLE IF NOT EXISTS tmp_current_keys (
                            Domain TEXT NOT NULL,
                            RuleId INTEGER NOT NULL,
                            PRIMARY KEY (Domain, RuleId)
                        )", _database, transaction))
                    {
                        createTemp.ExecuteNonQuery();
                    }

                    using (var clearTemp = new SQLiteCommand("DELETE FROM tmp_current_keys", _database, transaction))
                    {
                        clearTemp.ExecuteNonQuery();
                    }

                    using (var insertKey = new SQLiteCommand(
                        "INSERT OR IGNORE INTO tmp_current_keys (Domain, RuleId) VALUES (@domain, @ruleId)",
                        _database, transaction))
                    using (var upsertCommand = new SQLiteCommand(@"
                        INSERT INTO ET_Domain_Indicators
                        (Domain, MainDomain, RuleId, Description, Classification, Severity, RuleSource, FirstSeen, LastUpdated, IsActive)
                        VALUES (@domain, @mainDomain, @ruleId, @description, @classification, @severity, @ruleSource, @firstSeen, @lastUpdated, 1)
                        ON CONFLICT(Domain, RuleId) DO UPDATE SET
                            MainDomain = excluded.MainDomain,
                            Description = excluded.Description,
                            Classification = excluded.Classification,
                            Severity = excluded.Severity,
                            RuleSource = excluded.RuleSource,
                            FirstSeen = excluded.FirstSeen,
                            LastUpdated = excluded.LastUpdated,
                            IsActive = 1", _database, transaction))
                    {
                        foreach (var indicator in indicators)
                        {
                            if (indicator == null || string.IsNullOrEmpty(indicator.Domain))
                                continue;

                            var domainKey = indicator.Domain.Trim().ToLowerInvariant();
                            var mapKey = BuildDomainRuleKey(domainKey, indicator.RuleId);
                            currentKeys.Add(mapKey);

                            DateTime firstSeen;
                            if (indicator.MetadataCreatedAt.HasValue)
                            {
                                firstSeen = indicator.MetadataCreatedAt.Value;
                            }
                            else if (priorFirstSeen.TryGetValue(mapKey, out var prior))
                            {
                                firstSeen = prior;
                            }
                            else
                            {
                                firstSeen = now;
                            }

                            var lastUpdated = indicator.MetadataUpdatedAt ?? now;
                            var mainDomain = string.IsNullOrEmpty(indicator.MainDomain)
                                ? domainKey
                                : indicator.MainDomain.Trim().ToLowerInvariant();

                            insertKey.Parameters.Clear();
                            insertKey.Parameters.AddWithValue("@domain", domainKey);
                            insertKey.Parameters.AddWithValue("@ruleId", indicator.RuleId);
                            insertKey.ExecuteNonQuery();

                            upsertCommand.Parameters.Clear();
                            upsertCommand.Parameters.AddWithValue("@domain", domainKey);
                            upsertCommand.Parameters.AddWithValue("@mainDomain", mainDomain);
                            upsertCommand.Parameters.AddWithValue("@ruleId", indicator.RuleId);
                            upsertCommand.Parameters.AddWithValue("@description", indicator.Description ?? string.Empty);
                            upsertCommand.Parameters.AddWithValue("@classification", indicator.Classification ?? string.Empty);
                            upsertCommand.Parameters.AddWithValue("@severity", indicator.Severity ?? "low");
                            upsertCommand.Parameters.AddWithValue("@ruleSource", indicator.RuleSource ?? source);
                            upsertCommand.Parameters.AddWithValue("@firstSeen", firstSeen);
                            upsertCommand.Parameters.AddWithValue("@lastUpdated", lastUpdated);
                            upsertCommand.ExecuteNonQuery();
                        }
                    }

                    // Remove rows no longer present in this feed snapshot (no soft-delete history)
                    using (var orphanDelete = new SQLiteCommand(@"
                        DELETE FROM ET_Domain_Indicators
                        WHERE NOT EXISTS (
                            SELECT 1 FROM tmp_current_keys t
                            WHERE t.Domain = ET_Domain_Indicators.Domain
                              AND t.RuleId = ET_Domain_Indicators.RuleId
                        )", _database, transaction))
                    {
                        var orphansRemoved = orphanDelete.ExecuteNonQuery();
                        if (orphansRemoved > 0)
                        {
                            LogMessage($"ET RULES: Removed {orphansRemoved} orphan indicators not in current feed");
                        }
                    }

                    using (var dropTemp = new SQLiteCommand("DROP TABLE IF EXISTS tmp_current_keys", _database, transaction))
                    {
                        dropTemp.ExecuteNonQuery();
                    }

                    transaction.Commit();
                }

                // Log successful update
                await LogUpdateResult(indicators.Count, true, null);

                LogMessage($"ET RULES: Upserted {indicators.Count} indicators from {source} (unique keys={currentKeys.Count})");
            }
            catch (Exception ex)
            {
                LogMessage($"ET RULES ERROR: Failed to store indicators: {ex.Message}");
                await LogUpdateResult(0, false, ex.Message);
                throw;
            }
        }

        private Dictionary<string, DateTime> LoadPriorFirstSeenMap()
        {
            var map = new Dictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase);

            try
            {
                using (var command = new SQLiteCommand(
                    "SELECT Domain, RuleId, FirstSeen FROM ET_Domain_Indicators WHERE IsActive = 1", _database))
                using (var reader = command.ExecuteReader())
                {
                    int ordDomain = reader.GetOrdinal("Domain");
                    int ordRuleId = reader.GetOrdinal("RuleId");
                    int ordFirstSeen = reader.GetOrdinal("FirstSeen");

                    while (reader.Read())
                    {
                        if (reader.IsDBNull(ordDomain) || reader.IsDBNull(ordFirstSeen))
                            continue;

                        var domain = reader.GetString(ordDomain);
                        var ruleId = reader.IsDBNull(ordRuleId) ? 0 : Convert.ToInt32(reader.GetValue(ordRuleId));
                        var firstSeen = reader.GetDateTime(ordFirstSeen);
                        var key = BuildDomainRuleKey(domain, ruleId);

                        if (!map.ContainsKey(key))
                        {
                            map[key] = firstSeen;
                        }
                        else if (firstSeen < map[key])
                        {
                            map[key] = firstSeen;
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                LogMessage($"ET RULES ERROR: Failed to load prior FirstSeen map: {ex.Message}");
            }

            return map;
        }

        private async Task LogUpdateResult(int rulesCount, bool success, string errorMessage)
        {
            try
            {
                using (var logCommand = new SQLiteCommand(@"
                    INSERT INTO ET_Update_Log (UpdateTime, RuleSource, RulesCount, Success, ErrorMessage)
                    VALUES (@updateTime, @ruleSource, @rulesCount, @success, @errorMessage)", _database))
                {
                    // Determine actual rule source used
                    var ruleSource = "ET Open";
                    if (!string.IsNullOrEmpty(_etProApiKey))
                    {
                        try
                        {
                            using (var sourceCheck = new SQLiteCommand("SELECT COUNT(*) FROM ET_Domain_Indicators WHERE RuleSource LIKE '%ET Pro%' AND IsActive = 1", _database))
                            {
                                var etProCount = Convert.ToInt32(sourceCheck.ExecuteScalar());
                                ruleSource = etProCount > 0 ? "ET Pro" : "ET Open (ET Pro configured)";
                            }
                        }
                        catch
                        {
                            ruleSource = "ET Open";
                        }
                    }
                    
                    logCommand.Parameters.AddWithValue("@updateTime", DateTime.Now);
                    logCommand.Parameters.AddWithValue("@ruleSource", ruleSource);
                    logCommand.Parameters.AddWithValue("@rulesCount", rulesCount);
                    logCommand.Parameters.AddWithValue("@success", success);
                    logCommand.Parameters.AddWithValue("@errorMessage", errorMessage ?? (object)DBNull.Value);

                    logCommand.ExecuteNonQuery();
                }
            }
            catch (Exception ex)
            {
                LogMessage($"ET RULES ERROR: Failed to log update result: {ex.Message}");
            }
        }

        private void UpdateMemoryCache(List<ETDomainIndicator> indicators)
        {
            try
            {
                // Clear existing cache
                _etCache.Clear();

                // Pre-populate cache with high-priority indicators
                var highPriorityIndicators = indicators
                    .Where(i => i.Severity == "high")
                    .Take(1000) // Limit cache size
                    .ToList();

                foreach (var indicator in highPriorityIndicators)
                {
                    var etInfo = new ETDomainInfo
                    {
                        Domain = indicator.Domain,
                        RuleId = indicator.RuleId,
                        Description = indicator.Description,
                        Classification = indicator.Classification,
                        Severity = indicator.Severity,
                        Source = indicator.RuleSource,
                        LastUpdated = indicator.LastUpdated
                    };

                    _etCache.TryAdd(indicator.Domain, etInfo);
                }

                LogMessage($"ET RULES: Memory cache updated with {highPriorityIndicators.Count} high-priority indicators");
            }
            catch (Exception ex)
            {
                LogMessage($"ET RULES ERROR: Failed to update memory cache: {ex.Message}");
            }
        }

        private void WarmMemoryCacheFromDatabase()
        {
            try
            {
                _etCache.Clear();

                using (var command = new SQLiteCommand(@"
                    SELECT Domain, RuleId, Description, Classification, Severity, RuleSource, LastUpdated
                    FROM ET_Domain_Indicators
                    WHERE IsActive = 1 AND Severity = 'high'
                    ORDER BY LastUpdated DESC
                    LIMIT 1000", _database))
                using (var reader = command.ExecuteReader())
                {
                    int ordDomain = reader.GetOrdinal("Domain");
                    int ordRuleId = reader.GetOrdinal("RuleId");
                    int ordDesc = reader.GetOrdinal("Description");
                    int ordClass = reader.GetOrdinal("Classification");
                    int ordSev = reader.GetOrdinal("Severity");
                    int ordSource = reader.GetOrdinal("RuleSource");
                    int ordLU = reader.GetOrdinal("LastUpdated");

                    int loaded = 0;
                    while (reader.Read())
                    {
                        if (reader.IsDBNull(ordDomain))
                            continue;

                        var domain = reader.GetString(ordDomain);
                        var etInfo = new ETDomainInfo
                        {
                            Domain = domain,
                            RuleId = reader.IsDBNull(ordRuleId) ? 0 : Convert.ToInt32(reader.GetValue(ordRuleId)),
                            Description = reader.IsDBNull(ordDesc) ? string.Empty : reader.GetString(ordDesc),
                            Classification = reader.IsDBNull(ordClass) ? string.Empty : reader.GetString(ordClass),
                            Severity = reader.IsDBNull(ordSev) ? "high" : reader.GetString(ordSev),
                            Source = reader.IsDBNull(ordSource) ? string.Empty : reader.GetString(ordSource),
                            LastUpdated = reader.IsDBNull(ordLU) ? DateTime.MinValue : reader.GetDateTime(ordLU)
                        };

                        if (_etCache.TryAdd(domain, etInfo))
                            loaded++;
                    }

                    LogMessage($"ET RULES: Memory cache warmed from database with {loaded} high-priority indicators");
                }
            }
            catch (Exception ex)
            {
                LogMessage($"ET RULES ERROR: Failed to warm memory cache from database: {ex.Message}");
            }
        }

        private void LogMessage(string message)
        {
            try
            {
#if !BUILD_WITHOUT_FIDDLER
                FiddlerApplication.Log.LogString($"[ET-RULES] {message}");
#else
                Console.WriteLine($"[ET-RULES] {DateTime.Now:HH:mm:ss} {message}");
#endif
            }
            catch
            {
                // Ignore logging errors
            }
        }

        #endregion
    }

    #region Helper Classes

    /// <summary>
    /// Information about a domain from ET rules
    /// </summary>
    public class ETDomainInfo
    {
        public string Domain { get; set; }
        public int RuleId { get; set; }
        public string Description { get; set; }
        public string Classification { get; set; }
        public string Severity { get; set; }
        public string Source { get; set; }
        public DateTime LastUpdated { get; set; }
    }

    /// <summary>
    /// Domain indicator from ET rules
    /// </summary>
    internal class ETDomainIndicator
    {
        public string Domain { get; set; }
        public string MainDomain { get; set; }
        public int RuleId { get; set; }
        public string Description { get; set; }
        public string Classification { get; set; }
        public string Severity { get; set; }
        public string RuleSource { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastUpdated { get; set; }
        public DateTime? MetadataCreatedAt { get; set; }
        public DateTime? MetadataUpdatedAt { get; set; }
        public string Reference { get; set; }
        
        // Enhanced extraction metadata for better analysis
        public string ExtractionMethod { get; set; } // dns.query, tls.sni, http.host, Host-anchor, etc.
        public string Confidence { get; set; }      // High, Medium, Low based on extraction method
    }

    /// <summary>
    /// Helper class for database updates - replaces tuple syntax for .NET Framework 4.6.1 compatibility
    /// </summary>
    internal class DomainUpdate
    {
        public int Id { get; set; }
        public string Domain { get; set; }
    }

    #endregion
} 