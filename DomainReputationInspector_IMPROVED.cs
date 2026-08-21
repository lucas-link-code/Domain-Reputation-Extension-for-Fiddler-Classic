using System;
using System.Collections.Generic;
using System.Drawing;
using System.Windows.Forms;
using System.Linq;
using System.Threading.Tasks;
using System.IO;
using System.Collections.Concurrent;
using System.Reflection;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Globalization;
using System.Diagnostics;

#if !BUILD_WITHOUT_FIDDLER
using Fiddler;
#endif

[assembly: Fiddler.RequiredVersionAttribute("2.3.0.0")]

namespace DomainReputationInspector
{
    public class DomainReputationInspector : IFiddlerExtension
    {
        #region Private Fields

        private readonly ConcurrentDictionary<string, DomainTrackingInfo> _domainTracking = new ConcurrentDictionary<string, DomainTrackingInfo>();

        private VirusTotalService _virusTotalService;

        private DomainExtractor _domainExtractor;

        private EmergingThreatsRulesService _etRulesService;

        private DomainReputationUI _uiControl;

        private TabPage _tabPage;

        private bool _extensionLoaded = false;

        // Domains to hide from Fiddler session list
        private readonly HashSet<string> _hiddenDomains = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "virustotal.com",
            "www.virustotal.com",
            "generativelanguage.googleapis.com",
            "openai.com",
            "api.openai.com",
            "emergingthreats.net",
            "rules.emergingthreats.net"
        };

        #endregion

        #region IFiddlerExtension Implementation

        // Called when the extension is loaded
        public void OnLoad()
        {
            try
            {
                LogMessage("DOMAIN REPUTATION INSPECTOR WITH ET RULES - STARTING INITIALIZATION");
                
                // Initialize services
                _virusTotalService = new VirusTotalService();
                _domainExtractor = new DomainExtractor();
                try
                {
                    _etRulesService = new EmergingThreatsRulesService();
                }
                catch (Exception etEx)
                {
                    LogMessage("ET RULES DISABLED: " + etEx.Message);
                    _etRulesService = null; // Continue without ET rules rather than failing the whole extension
                }
                
                LogMessage("ALL SERVICES INITIALIZED (VT + ET Rules)");
                
                Task.Run(() => CreateUIAsync());
                
#if !BUILD_WITHOUT_FIDDLER
                FiddlerApplication.AfterSessionComplete += OnAfterSessionComplete;
                FiddlerApplication.BeforeRequest += OnBeforeRequest;
#endif
                
                _extensionLoaded = true;
                LogMessage("=== DOMAIN REPUTATION INSPECTOR LOADED SUCCESSFULLY ===");
                LogMessage("MONITORING MODE: Captures domains and retrieves existing reputation data");
                LogMessage("ANALYSIS MODE: No new VirusTotal analysis will be triggered");
                LogMessage("REPORTING MODE: Uses cached/existing domain reports from VirusTotal");
                
                ShowSuccessNotification();
            }
            catch (Exception ex)
            {
                LogMessage("CRITICAL ERROR during extension loading: " + ex.Message);
                LogMessage("Stack trace: " + ex.StackTrace);
            }
        }

        public void OnBeforeUnload()
        {
            try
            {
                LogMessage("DOMAIN REPUTATION INSPECTOR - PREPARING TO SHUTDOWN");
                
                // Perform any cleanup before unloading
                _extensionLoaded = false;
            }
            catch (Exception ex)
            {
                LogMessage("ERROR during extension pre-unload: " + ex.Message);
            }
        }

        public void OnUnload()
        {
            try
            {
                LogMessage("DOMAIN REPUTATION INSPECTOR - SHUTTING DOWN");
                
                // Unhook from Fiddler events
#if !BUILD_WITHOUT_FIDDLER
                FiddlerApplication.AfterSessionComplete -= OnAfterSessionComplete;
                FiddlerApplication.BeforeRequest -= OnBeforeRequest;
#endif
                
                // Dispose services
                _virusTotalService?.Dispose();
                _domainExtractor?.Dispose();
                _etRulesService?.Dispose();
                
                // Remove UI
                if (_tabPage != null)
                {
#if !BUILD_WITHOUT_FIDDLER
                    FiddlerApplication.UI.Invoke(new Action(() =>
                    {
                        try
                        {
                            FiddlerApplication.UI.tabsViews.TabPages.Remove(_tabPage);
                        }
                        catch (Exception ex)
                        {
                            LogMessage("Error removing tab: " + ex.Message);
                        }
                    }));
#endif
                }
                
                LogMessage("DOMAIN REPUTATION INSPECTOR - SHUTDOWN COMPLETE");
            }
            catch (Exception ex)
            {
                LogMessage("ERROR during extension unloading: " + ex.Message);
            }
        }

        #endregion

        #region Private Methods

        private void ShowSuccessNotification()
        {
            try
            {
#if !BUILD_WITHOUT_FIDDLER
                Task.Run(async () =>
                {
                    await Task.Delay(3000);
                    
                    FiddlerApplication.UI.Invoke(new Action(() =>
                    {
                        try
                        {
                            MessageBox.Show(
                                "Domain Reputation Inspector has been loaded successfully!\n\n" +
                                "Extension is now monitoring web traffic\n" +
                                "Retrieves existing domain reputation data only",
                                "Domain Reputation Inspector",
                                MessageBoxButtons.OK,
                                MessageBoxIcon.Information);
                        }
                        catch (Exception ex)
                        {
                            LogMessage("ERROR showing success notification: " + ex.Message);
                        }
                    }));
                });
#endif
            }
            catch (Exception ex)
            {
                LogMessage("ERROR showing success notification: " + ex.Message);
            }
        }

        private async Task CreateUIAsync()
        {
            try
            {
                await Task.Delay(2000);
                
                LogMessage("CREATING UI COMPONENTS");
                
#if !BUILD_WITHOUT_FIDDLER
                FiddlerApplication.UI.Invoke(new Action(() =>
                {
                    try
                    {
                        if (FiddlerApplication.UI == null || FiddlerApplication.UI.tabsViews == null)
                        {
                            LogMessage("UI not ready yet; retrying in 1s...");
                            Task.Run(async () => { await Task.Delay(1000); await CreateUIAsync(); });
                            return;
                        }

                        _uiControl = new DomainReputationUI();
                        _uiControl.Dock = DockStyle.Fill;
                        
                        _uiControl.SetVirusTotalService(_virusTotalService);
                        _uiControl.SetETRulesService(_etRulesService);
                        _uiControl.SetDomainTracking(_domainTracking);
#if PUBLIC_RELEASE
                        _uiControl.ApiKeyChanged += OnApiKeyChanged;
#endif
                        _uiControl.RefreshRequested += OnRefreshRequested;
                        _uiControl.ClearRequested += OnClearRequested;
                        _uiControl.DomainSelected += OnDomainSelected;
                        
                        _tabPage = new TabPage("Domain Reputation");
                        _tabPage.Controls.Add(_uiControl);
                        
                        // Add to Fiddler UI
                        FiddlerApplication.UI.tabsViews.TabPages.Add(_tabPage);
                        
                        LogMessage("UI COMPONENTS CREATED SUCCESSFULLY");
                    }
                    catch (Exception ex)
                    {
                        LogMessage("ERROR creating UI: " + ex.Message);
                        Task.Run(async () => { await Task.Delay(1000); await CreateUIAsync(); });
                    }
                }));
#endif
            }
            catch (Exception ex)
            {
                LogMessage("ERROR in CreateUIAsync: " + ex.Message);
            }
        }

        private void OnBeforeRequest(Session oSession)
        {
            try
            {
                if (!_extensionLoaded)
                    return;

                // Check if this session should be hidden from Fiddler UI
                var hostname = oSession.hostname;
                if (!string.IsNullOrEmpty(hostname))
                {
                    // Check exact match and wildcard match for hidden domains
                    if (ShouldHideSession(hostname))
                    {
                        // Method 1: Mark session as hidden using Fiddler's built-in flags
                        oSession["ui-hide"] = "true";
                        oSession["ui-backcolor"] = "Transparent"; // Make background transparent
                        
                        // Method 2: Mark session to be removed after completion
                        oSession["x-AutoRemove"] = "true";
                        
                        LogMessage($"[SESSION-FILTER] Marking session for hiding: {hostname}");
                    }
                }
            }
            catch (Exception ex)
            {
                LogMessage($"[SESSION-FILTER] Error in OnBeforeRequest: {ex.Message}");
            }
        }

        private void OnAfterSessionComplete(Session oSession)
        {
            try
            {
                if (!_extensionLoaded)
                    return;

                // Check if this session should be auto-hidden
                if (oSession["x-AutoRemove"] == "true")
                {
                    // Apply visual hiding instead of removal to avoid API complications
                    oSession["ui-color"] = "lightgray";
                    oSession["ui-comments"] = "Hidden API call";
                    oSession["ui-hide"] = "true";
                    
                    LogMessage($"[SESSION-FILTER] Applied visual hiding to session for {oSession.hostname}");
                    return; // Don't process this session for domain reputation
                }
                
                var domain = ExtractDomainFromSession(oSession);
                if (string.IsNullOrEmpty(domain))
                    return;
                
                // ENHANCED SUBDOMAIN CAPTURE:
                // Capture and display full subdomains from Fiddler traffic (e.g., "api.evil.linkedin-phish.com")
                // Benefits:
                // 1. More accurate VirusTotal ratings (subdomain-specific reputation)
                // 2. Better traffic analysis (see exact endpoints being accessed)  
                // 3. Intelligent ET matching (exact + fallback to base domain)
                // 4. Preserves full forensic detail of network activity
                var exactDomain = domain; // Full subdomain preserved for maximum detail
                
                var trackingInfo = _domainTracking.AddOrUpdate(exactDomain, 
                    new DomainTrackingInfo 
                    { 
                        Domain = exactDomain, 
                        FirstSeen = DateTime.Now, 
                        RequestCount = 1,
                        ApiCallsMade = 0
                    },
                    // Existing domain - just increment counter
                    (key, existing) => 
                    {
                        existing.RequestCount++;
                        existing.LastSeen = DateTime.Now;
                        return existing;
                    });

                // Only make API call for truly new domains
                if (trackingInfo.RequestCount == 1 && trackingInfo.ApiCallsMade == 0)
                {
                    LogMessage("NEW DOMAIN: " + exactDomain + " (first encounter)");
                    
                    trackingInfo.ApiCallsMade += 1;
                    
                    _uiControl?.AddDomain(exactDomain);
                    _uiControl?.UpdateDomainCounters(exactDomain, trackingInfo.RequestCount, trackingInfo.ApiCallsMade);
                    
                    // Check ET rules with intelligent subdomain matching
                    var etInfo = CheckETRulesIntelligent(exactDomain);
                    if (etInfo != null)
                    {
                        LogMessage($"ET MATCH: {exactDomain} - {etInfo.Severity.ToUpper()}: {etInfo.Description}");
                        _uiControl?.UpdateETInformation(exactDomain, etInfo);
                    }
                    
                    // Then query VirusTotal with full subdomain for maximum accuracy
                    // Subdomains provide more specific reputation data than base domains
                    QueryDomainReputationAsync(exactDomain);
                }
                else
                {
                    LogMessage("DOMAIN COUNTER: " + exactDomain + " seen " + trackingInfo.RequestCount + " times (no new API call)");
                    _uiControl?.UpdateDomainCounters(exactDomain, trackingInfo.RequestCount, trackingInfo.ApiCallsMade);
                }
            }
            catch (Exception ex)
            {
                LogMessage("ERROR processing session: " + ex.Message);
            }
        }

        /// <summary>
        /// Intelligent ET rules checking - tries exact domain first, then base domain
        /// This provides comprehensive threat detection for subdomains
        /// </summary>
        private ETDomainInfo CheckETRulesIntelligent(string fullDomain)
        {
            if (string.IsNullOrEmpty(fullDomain) || _etRulesService == null)
                return null;

            try
            {
                // First try exact domain match (e.g., "api.malicious.linkedin-phish.com")
                var exactMatch = _etRulesService.CheckDomain(fullDomain);
                if (exactMatch != null)
                {
                    LogMessage($"ET EXACT MATCH: {fullDomain} found in threat database");
                    return exactMatch;
                }

                // If no exact match, try base domain for broader threat detection
                var baseDomain = _domainExtractor.ExtractMainDomain(fullDomain);
                if (!string.IsNullOrEmpty(baseDomain) && !baseDomain.Equals(fullDomain, StringComparison.OrdinalIgnoreCase))
                {
                    var baseMatch = _etRulesService.CheckDomain(baseDomain);
                    if (baseMatch != null)
                    {
                        LogMessage($"ET BASE MATCH: {fullDomain} matched via base domain {baseDomain}");
                        // Enhance description to show it's a subdomain match
                        var enhancedMatch = new ETDomainInfo
                        {
                            Domain = fullDomain, // Keep the actual subdomain being queried
                            RuleId = baseMatch.RuleId,
                            Description = $"{baseMatch.Description} (detected via {baseDomain})",
                            Classification = baseMatch.Classification,
                            Severity = baseMatch.Severity,
                            Source = baseMatch.Source,
                            LastUpdated = baseMatch.LastUpdated
                        };
                        return enhancedMatch;
                    }
                }

                // No threats found
                return null;
            }
            catch (Exception ex)
            {
                LogMessage($"ERROR in intelligent ET check for {fullDomain}: {ex.Message}");
                return null;
            }
        }

        private bool ShouldHideSession(string hostname)
        {
            if (string.IsNullOrEmpty(hostname))
                return false;

            // Check exact matches first
            if (_hiddenDomains.Contains(hostname))
                return true;

            // Check if hostname ends with any of our hidden domains (for subdomains)
            foreach (var hiddenDomain in _hiddenDomains)
            {
                if (hostname.EndsWith("." + hiddenDomain, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        private string ExtractDomainFromSession(Session oSession)
        {
            try
            {
                var hostname = oSession.hostname;
                if (string.IsNullOrEmpty(hostname))
                    return null;
                
                if (hostname.Equals("localhost", StringComparison.OrdinalIgnoreCase) ||
                    hostname.Equals("127.0.0.1", StringComparison.OrdinalIgnoreCase) ||
                    System.Net.IPAddress.TryParse(hostname, out _))
                {
                    return null;
                }
                
                if (!oSession.isHTTPS && !oSession.fullUrl.StartsWith("http://", StringComparison.OrdinalIgnoreCase))
                    return null;
                
                return hostname;
            }
            catch (Exception ex)
            {
                LogMessage("ERROR extracting domain: " + ex.Message);
                return null;
            }
        }

        private void QueryDomainReputationAsync(string domain)
        {
            try
            {
                LogMessage("SINGLE API CALL: Querying existing reputation data for " + domain);
                
                _virusTotalService.QueryDomainReputationAsync(domain, (queryDomain, malicious, suspicious, harmless, undetected, error) =>
                {
                    try
                    {
                        LogMessage($"VT CALLBACK RECEIVED: {queryDomain} - M:{malicious}, S:{suspicious}, H:{harmless}, U:{undetected}, Error:{error}");
                        if (!string.IsNullOrEmpty(error))
                        {
                            LogMessage("WARNING: VirusTotal query error for " + queryDomain + ": " + error);
                            _uiControl?.UpdateDomainReputation(queryDomain, 0, 0, 0, 0, error);
                        }
                        else
                        {
                            LogMessage("REPUTATION DATA RETRIEVED FOR " + queryDomain + ": M:" + malicious + ", S:" + suspicious + ", H:" + harmless + ", U:" + undetected);
                            _uiControl?.UpdateDomainReputation(queryDomain, malicious, suspicious, harmless, undetected, null);
                        }
                    }
                    catch (Exception ex)
                    {
                        LogMessage("ERROR processing reputation callback: " + ex.Message);
                    }
                });
            }
            catch (Exception ex)
            {
                LogMessage("ERROR querying domain reputation: " + ex.Message);
            }
        }

        private void OnApiKeyChanged(object sender, string apiKey)
        {
            if (string.IsNullOrEmpty(apiKey))
                return;

            try
            {
                _virusTotalService?.SetApiKey(apiKey);
                LogMessage("VT API KEY: User key applied");
            }
            catch (Exception ex)
            {
                LogMessage("ERROR applying VT API key: " + ex.Message);
            }
        }

        private void OnDomainSelected(object sender, string domain)
        {
            if (string.IsNullOrEmpty(domain))
                return;

            try
            {
                string url = "https://www.virustotal.com/gui/domain/" + domain;
                Process.Start(url);
            }
            catch (Exception ex)
            {
                LogMessage("ERROR opening VirusTotal report: " + ex.Message);
            }
        }

        private void OnRefreshRequested(object sender, string domain)
        {
            try
            {
                if (string.IsNullOrEmpty(domain)) return;

                LogMessage($"REFRESH REQUESTED: {domain}");

                var tracking = _domainTracking.AddOrUpdate(domain,
                    new DomainTrackingInfo
                    {
                        Domain = domain,
                        FirstSeen = DateTime.Now,
                        LastSeen = DateTime.Now,
                        RequestCount = 0,
                        ApiCallsMade = 1
                    },
                    (key, existing) =>
                    {
                        existing.ApiCallsMade += 1; // manual refresh increments counter
                        existing.LastSeen = DateTime.Now;
                        LogMessage($"REFRESH COUNTER: {domain} now has {existing.ApiCallsMade} API calls made");
                        return existing;
                    });

                // Update UI with new counter immediately
                _uiControl?.UpdateDomainCounters(domain, tracking.RequestCount, tracking.ApiCallsMade);
                LogMessage($"UI UPDATED: {domain} - Requests: {tracking.RequestCount}, ApiCalls: {tracking.ApiCallsMade}");
                
                // Force a fresh VT query bypassing cache for this specific domain
                _virusTotalService.ClearCache(domain);
                QueryDomainReputationAsync(domain);
            }
            catch (Exception ex)
            {
                LogMessage("ERROR handling refresh: " + ex.Message);
            }
        }

        private void OnClearRequested(object sender, EventArgs e)
        {
            try
            {
                _domainTracking.Clear();
                _uiControl?.ClearDomains();
            }
            catch (Exception ex)
            {
                LogMessage("ERROR handling clear: " + ex.Message);
            }
        }

        public string GetStatistics()
        {
            var totalDomains = _domainTracking.Count;
            var totalRequests = _domainTracking.Values.Sum(d => d.RequestCount);
            var domainsWithApiCalls = _domainTracking.Values.Count(d => d.ApiCallsMade > 0);
            
            return "Domains: " + totalDomains + ", Total Requests: " + totalRequests + ", API Calls Made: " + domainsWithApiCalls;
        }

        private void LogMessage(string message)
        {
#if !BUILD_WITHOUT_FIDDLER
            FiddlerApplication.Log.LogString("[DomainRep] " + message);
#else
            Console.WriteLine("[" + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss") + "] [DomainRep] " + message);
#endif
        }

        #endregion
    }

    public class DomainTrackingInfo
    {
        public string Domain { get; set; }
        public DateTime FirstSeen { get; set; }
        public DateTime LastSeen { get; set; }
        public int RequestCount { get; set; }
        public int ApiCallsMade { get; set; }
    }



    // (Removed duplicate DomainReputationUI definition; using the dedicated partial class in DomainReputationUI.cs + Designer)

    // Domain reputation data item
    public class DomainReputationItem
    {
        public string Domain { get; set; }
        public DateTime FirstSeen { get; set; }  
        public DateTime LastSeen { get; set; }  
        public int Requests { get; set; }
        public int ApiCallsMade { get; set; }
        public int Malicious { get; set; }
        public int Suspicious { get; set; }
        public int Harmless { get; set; }
        public int Undetected { get; set; }
        public string Status { get; set; }
        public string Error { get; set; }
    }
} 