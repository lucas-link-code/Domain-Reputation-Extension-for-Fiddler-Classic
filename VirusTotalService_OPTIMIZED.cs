using System;
using System.Collections.Concurrent;
using System.Net.Http;
using System.Net;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;

#if !BUILD_WITHOUT_FIDDLER
using Fiddler;
#endif

namespace DomainReputationInspector
{
    public partial class VirusTotalService : IDisposable
    {
        #region Private Fields

        private readonly HttpClient _httpClient;

        // API key for VirusTotal
        private string _apiKey;

        private readonly ConcurrentDictionary<string, DomainReputationResult> _cache = new ConcurrentDictionary<string, DomainReputationResult>();

        private readonly ConcurrentDictionary<string, TaskCompletionSource<DomainReputationResult>> _pendingRequests = 
            new ConcurrentDictionary<string, TaskCompletionSource<DomainReputationResult>>();

        private readonly ConcurrentDictionary<string, List<Action<string, int, int, int, int, string>>> _pendingCallbacks = 
            new ConcurrentDictionary<string, List<Action<string, int, int, int, int, string>>>();

        private readonly SemaphoreSlim _rateLimitSemaphore = new SemaphoreSlim(1, 1);

        private readonly Timer _rateLimitTimer;

        private DateTime _lastRequestTime = DateTime.MinValue;

        private readonly TimeSpan _minRequestInterval = TimeSpan.FromSeconds(2);

        private readonly CancellationTokenSource _cancellationTokenSource = new CancellationTokenSource();

        private bool _disposed = false;

        private readonly object _callbackLock = new object();

        #endregion

        #region Constructor and Disposal

        // start VirusTotal service
        public VirusTotalService()
        {
            // Configure SSL certificate validation for VM/Fiddler environments (.NET Framework 4.6.1 compatible)
            ConfigureSSLForVMEnvironment();
            
            _httpClient = new HttpClient();
            _httpClient.DefaultRequestHeaders.Add("User-Agent", "DomainReputationInspector/1.0 (Optimized)");
            
            _rateLimitTimer = new Timer(ReleaseSemaphore, null, Timeout.Infinite, Timeout.Infinite);

            AfterServiceConstructed();
        }

        partial void AfterServiceConstructed();

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed)
            {
                if (disposing)
                {
                    _cancellationTokenSource.Cancel();
                    _rateLimitTimer?.Dispose();
                    _httpClient?.Dispose();
                    _rateLimitSemaphore?.Dispose();
                    _cancellationTokenSource?.Dispose();
                    
                    // Note: We don't restore the original ServicePointManager callback here
                    // because it's a global setting that other parts of the application might depend on
                }
                _disposed = true;
            }
        }

        #endregion

        #region Public Properties

        // API key property
        public string ApiKey
        {
            get { return _apiKey; }
            set 
            { 
                _apiKey = value;
                if (_httpClient != null)
                {
                    _httpClient.DefaultRequestHeaders.Remove("x-apikey");
                    if (!string.IsNullOrEmpty(_apiKey))
                    {
                        _httpClient.DefaultRequestHeaders.Add("x-apikey", _apiKey);
                    }
                }
            }
        }

        #endregion

        #region Public Methods

        // Set the API key
        public void SetApiKey(string apiKey)
        {
            ApiKey = apiKey;
        }

        public void QueryDomainReputationAsync(string domain, Action<string, int, int, int, int, string> callback)
        {
            if (string.IsNullOrEmpty(domain))
            {
                callback(domain, 0, 0, 0, 0, "Domain is null or empty");
                return;
            }

            if (string.IsNullOrEmpty(_apiKey))
            {
                callback(domain, 0, 0, 0, 0, "API key not configured");
                return;
            }

            // Check cache first
            if (_cache.TryGetValue(domain, out DomainReputationResult cachedResult))
            {
                var cacheAge = DateTime.Now - cachedResult.Timestamp;
                if (cacheAge.TotalMinutes < 30) // Use cache for 30 minutes
                {
                    LogMessage($"CACHE HIT: Using cached data for {domain} (age: {cacheAge.TotalMinutes:F1} minutes)");
                    callback(domain, cachedResult.MaliciousCount, cachedResult.SuspiciousCount, 
                            cachedResult.HarmlessCount, cachedResult.UndetectedCount, cachedResult.Error);
                    return;
                }
                else
                {
                    LogMessage($"CACHE EXPIRED: Data for {domain} is {cacheAge.TotalMinutes:F1} minutes old");
                }
            }

            lock (_callbackLock)
            {
                if (_pendingRequests.ContainsKey(domain))
                {
                    LogMessage($"REQUEST PENDING: Adding callback to existing request for {domain}");
                    
                    if (!_pendingCallbacks.ContainsKey(domain))
                    {
                        _pendingCallbacks[domain] = new List<Action<string, int, int, int, int, string>>();
                    }
                    _pendingCallbacks[domain].Add(callback);
                    return;
                }

                //  new request
                LogMessage($"NEW REQUEST: Starting API call for {domain}");
                var tcs = new TaskCompletionSource<DomainReputationResult>();
                _pendingRequests[domain] = tcs;
                
                // Initialize callback list
                _pendingCallbacks[domain] = new List<Action<string, int, int, int, int, string>> { callback };
            }

            // Execute the API request asynchronously
            Task.Run(async () =>
            {
                try
                {
                    var result = await QueryDomainReputationInternalAsync(domain);
                    
                    // Complete the task and notify all waiting callbacks
                    lock (_callbackLock)
                    {
                        if (_pendingRequests.TryRemove(domain, out var tcs))
                        {
                            tcs.SetResult(result);
                        }

                        if (_pendingCallbacks.TryRemove(domain, out var callbacks))
                        {
                            LogMessage($"NOTIFYING: {callbacks.Count} callbacks for {domain}");
                            foreach (var cb in callbacks)
                            {
                                try
                                {
                                    cb(domain, result.MaliciousCount, result.SuspiciousCount,
                                       result.HarmlessCount, result.UndetectedCount, result.Error);
                                }
                                catch (Exception ex)
                                {
                                    LogMessage($"ERROR in callback for {domain}: {ex.Message}");
                                }
                            }
                        }
                    }
                }
                catch (Exception ex)
                {
                    LogMessage($"ERROR querying domain {domain}: {ex.Message}");
                    
                    // Notify all waiting callbacks of the error
                    lock (_callbackLock)
                    {
                        if (_pendingRequests.TryRemove(domain, out var tcs))
                        {
                            tcs.SetException(ex);
                        }

                        if (_pendingCallbacks.TryRemove(domain, out var callbacks))
                        {
                            foreach (var cb in callbacks)
                            {
                                try
                                {
                                    cb(domain, 0, 0, 0, 0, $"Error: {ex.Message}");
                                }
                                catch (Exception callbackEx)
                                {
                                    LogMessage($"ERROR in error callback for {domain}: {callbackEx.Message}");
                                }
                            }
                        }
                    }
                }
            });
        }

        public void ClearCache()
        {
            _cache.Clear();
            _pendingRequests.Clear();
            _pendingCallbacks.Clear();
            LogMessage("CACHE CLEARED: All cached data and pending requests removed");
        }

        public void ClearCache(string domain)
        {
            if (string.IsNullOrEmpty(domain))
                return;

            _cache.TryRemove(domain, out _);
            _pendingRequests.TryRemove(domain, out _);
            _pendingCallbacks.TryRemove(domain, out _);
            LogMessage($"CACHE CLEARED: Removed cached data for {domain}");
        }

        #endregion

        #region Private Methods

        private void ConfigureSSLForVMEnvironment()
        {
            try
            {
                // Store the original certificate validation callback
                var originalCallback = ServicePointManager.ServerCertificateValidationCallback;
                
                // Set up custom certificate validation for VM/Fiddler environments (.NET Framework 4.6.1 compatible)
                ServicePointManager.ServerCertificateValidationCallback = (sender, certificate, chain, sslPolicyErrors) =>
                {
                    // Check if this is a trusted API domain that needs SSL bypass
                    var request = sender as HttpWebRequest;
                    if (request != null)
                    {
                        var host = request.RequestUri.Host.ToLower();
                        if (host.EndsWith("virustotal.com") || host == "virustotal.com" ||
                            host.EndsWith("emergingthreats.net") || host == "emergingthreats.net" ||
                            host.EndsWith("googleapis.com") || host == "googleapis.com" ||
                            host.EndsWith("openai.com") || host == "openai.com")
                        {
                            LogMessage($"[SSL-BYPASS] Bypassing certificate validation for {host} in VM/Fiddler environment");
                            return true; // Trust these API domains to bypass Fiddler certificate issues
                        }
                    }
                    
                    // For other domains, use the original callback or default validation
                    if (originalCallback != null)
                    {
                        return originalCallback(sender, certificate, chain, sslPolicyErrors);
                    }
                    
                    // Default validation: accept only if no SSL policy errors
                    return sslPolicyErrors == SslPolicyErrors.None;
                };
                
                LogMessage("[VT-SSL] SSL certificate validation configured for VM/Fiddler environment");
            }
            catch (Exception ex)
            {
                LogMessage($"[VT-SSL] WARNING: Failed to configure SSL bypass: {ex.Message}");
            }
        }

        private async Task<DomainReputationResult> QueryDomainReputationInternalAsync(string domain)
        {
            if (_disposed || _cancellationTokenSource.Token.IsCancellationRequested)
            {
                throw new OperationCanceledException("Service is being disposed");
            }

            try
            {
                await _rateLimitSemaphore.WaitAsync(_cancellationTokenSource.Token);

                try
                {
                    var timeSinceLastRequest = DateTime.Now - _lastRequestTime;
                    if (timeSinceLastRequest < _minRequestInterval)
                    {
                        var delay = _minRequestInterval - timeSinceLastRequest;
                        LogMessage($"RATE LIMITING: Waiting {delay.TotalSeconds:F1} seconds before requesting {domain}");
                        await Task.Delay(delay, _cancellationTokenSource.Token);
                    }

                    _lastRequestTime = DateTime.Now;

                    // Make the API request
                    var result = await MakeApiRequestAsync(domain);

                    // Cache the result
                    _cache.AddOrUpdate(domain, result, (key, oldValue) => result);
                    LogMessage($"CACHED: Stored reputation data for {domain}");

                    return result;
                }
                finally
                {
                    _rateLimitTimer.Change(_minRequestInterval, Timeout.InfiniteTimeSpan);
                }
            }
            catch (OperationCanceledException)
            {
                // Service is being disposed
                throw;
            }
            catch (Exception ex)
            {
                _rateLimitSemaphore.Release();
                throw new Exception($"Failed to query domain reputation: {ex.Message}", ex);
            }
        }

        // Make the actual API request to VirusTotal
        private async Task<DomainReputationResult> MakeApiRequestAsync(string domain)
        {
            var result = new DomainReputationResult
            {
                Domain = domain,
                Timestamp = DateTime.Now
            };

            try
            {
                // Use GET endpoint to retrieve existing domain reports only
                var url = $"https://www.virustotal.com/api/v3/domains/{domain}";
                
                LogMessage($"API REQUEST: GET {url} (EXISTING REPORT ONLY)");
                
                var response = await _httpClient.GetAsync(url, _cancellationTokenSource.Token);

                if (response.IsSuccessStatusCode)
                {
                    var content = await response.Content.ReadAsStringAsync();
                    var jsonData = JObject.Parse(content);

                    LogMessage($"API SUCCESS: Retrieved existing domain report for {domain}");

                    // Parse the response
                    var attributes = jsonData["data"]?["attributes"];
                    if (attributes != null)
                    {
                        var lastAnalysisStats = attributes["last_analysis_stats"];
                        var lastAnalysisDate = attributes["last_analysis_date"];
                        
                        if (lastAnalysisStats != null)
                        {
                            result.MaliciousCount = lastAnalysisStats["malicious"]?.Value<int>() ?? 0;
                            result.SuspiciousCount = lastAnalysisStats["suspicious"]?.Value<int>() ?? 0;
                            result.HarmlessCount = lastAnalysisStats["harmless"]?.Value<int>() ?? 0;
                            result.UndetectedCount = lastAnalysisStats["undetected"]?.Value<int>() ?? 0;
                            
                            if (lastAnalysisDate != null)
                            {
                                var analysisTimestamp = DateTimeOffset.FromUnixTimeSeconds(lastAnalysisDate.Value<long>()).DateTime;
                                var analysisAge = DateTime.Now - analysisTimestamp;
                                LogMessage($"ANALYSIS AGE: {analysisAge.TotalDays:F1} days old (from {analysisTimestamp:yyyy-MM-dd HH:mm:ss})");
                            }
                            
                            LogMessage($"REPUTATION: {domain} = M:{result.MaliciousCount}, S:{result.SuspiciousCount}, H:{result.HarmlessCount}, U:{result.UndetectedCount}");
                        }
                        else
                        {
                            LogMessage($"WARNING: No analysis stats found for {domain}");
                            result.Error = "No analysis statistics available";
                        }
                    }
                    else
                    {
                        LogMessage($"WARNING: No attributes found in response for {domain}");
                        result.Error = "No domain attributes found";
                    }
                }
                else if (response.StatusCode == System.Net.HttpStatusCode.NotFound)
                {
                    LogMessage($"NOT FOUND: {domain} not in VirusTotal database");
                    result.Error = "Domain not found in VirusTotal database";
                }
                else if ((int)response.StatusCode == 429)
                {
                    LogMessage($"RATE LIMIT: Exceeded for {domain}");
                    result.Error = "Rate limit exceeded. Please wait or upgrade your API plan.";
                }
                else if (response.StatusCode == System.Net.HttpStatusCode.Forbidden)
                {
                    LogMessage($"FORBIDDEN: Invalid API key for {domain}");
                    result.Error = "Invalid API key or insufficient permissions";
                }
                else
                {
                    var errorContent = await response.Content.ReadAsStringAsync();
                    LogMessage($"HTTP ERROR: {(int)response.StatusCode} {response.ReasonPhrase} for {domain}");
                    result.Error = $"HTTP {(int)response.StatusCode}: {response.ReasonPhrase}";
                }
            }
            catch (TaskCanceledException)
            {
                LogMessage($"TIMEOUT: Request timeout for {domain}");
                result.Error = "Request timeout";
            }
            catch (HttpRequestException ex)
            {
                LogMessage($"NETWORK ERROR: {ex.Message} for {domain}");
                result.Error = $"Network error: {ex.Message}";
            }
            catch (JsonException ex)
            {
                LogMessage($"JSON ERROR: Failed to parse response for {domain}: {ex.Message}");
                result.Error = $"Failed to parse response: {ex.Message}";
            }
            catch (Exception ex)
            {
                LogMessage($"UNEXPECTED ERROR: {ex.Message} for {domain}");
                result.Error = $"Unexpected error: {ex.Message}";
            }

            return result;
        }

        private void ReleaseSemaphore(object state)
        {
            try
            {
                _rateLimitSemaphore.Release();
            }
            catch (ObjectDisposedException)
            {
                // Service is being disposed
            }
        }

        private void LogMessage(string message)
        {
#if !BUILD_WITHOUT_FIDDLER
            FiddlerApplication.Log.LogString($"[VT-OPTIMIZED] {message}");
#else
            Console.WriteLine($"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] [VT-OPTIMIZED] {message}");
#endif
        }

        #endregion

        #region Nested Classes

        // Domain reputation result data
        private class DomainReputationResult
        {
            public string Domain { get; set; }
            public int MaliciousCount { get; set; }
            public int SuspiciousCount { get; set; }
            public int HarmlessCount { get; set; }
            public int UndetectedCount { get; set; }
            public string Error { get; set; }
            public DateTime Timestamp { get; set; }
        }

        #endregion
    }
} 