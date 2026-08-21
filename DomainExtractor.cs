using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;

namespace DomainReputationInspector
{
    /// <summary>
    /// Utility class for extracting and normalizing domain names
    /// </summary>
    public class DomainExtractor : IDisposable
    {
        #region Private Fields

        /// <summary>
        /// Common second-level domains that should be preserved
        /// </summary>
        private readonly HashSet<string> _commonSLDs = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "co.uk", "co.jp", "co.kr", "co.in", "co.za", "co.nz", "co.au",
            "com.au", "com.br", "com.cn", "com.mx", "com.tr", "com.tw",
            "net.au", "net.br", "net.cn", "net.uk",
            "org.uk", "org.au", "org.br", "org.cn",
            "edu.au", "edu.br", "edu.cn", "edu.uk",
            "gov.uk", "gov.au", "gov.br", "gov.cn",
            "ac.uk", "ac.jp", "ac.kr", "ac.cn",
            "ne.jp", "or.jp", "gr.jp", "go.jp",
            "ltd.uk", "plc.uk", "me.uk"
        };

        /// <summary>
        /// Regex pattern for validating domain names
        /// </summary>
        private readonly Regex _domainRegex = new Regex(
            @"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$",
            RegexOptions.Compiled | RegexOptions.IgnoreCase);

        /// <summary>
        /// Regex pattern for extracting IPv4 addresses
        /// </summary>
        private readonly Regex _ipv4Regex = new Regex(
            @"^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$",
            RegexOptions.Compiled);

        /// <summary>
        /// Regex pattern for extracting IPv6 addresses
        /// </summary>
        private readonly Regex _ipv6Regex = new Regex(
            @"^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$",
            RegexOptions.Compiled);

        #endregion

        #region Public Methods

        /// <summary>
        /// Extracts the main domain from a hostname, handling subdomains, www prefixes, and common SLDs
        /// </summary>
        /// <param name="hostname">The hostname to extract the domain from</param>
        /// <returns>The normalized main domain, or null if invalid</returns>
        public string ExtractMainDomain(string hostname)
        {
            if (string.IsNullOrEmpty(hostname))
                return null;

            try
            {
                // Clean the hostname
                hostname = CleanHostname(hostname);

                // Skip IP addresses
                if (IsIpAddress(hostname))
                    return null;

                // Skip localhost and local domains
                if (IsLocalDomain(hostname))
                    return null;

                // Validate domain format
                if (!IsValidDomain(hostname))
                    return null;

                // Extract main domain
                return ExtractMainDomainInternal(hostname);
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>
        /// Checks if a hostname is a valid domain name
        /// </summary>
        /// <param name="hostname">The hostname to validate</param>
        /// <returns>True if valid, false otherwise</returns>
        public bool IsValidDomain(string hostname)
        {
            if (string.IsNullOrEmpty(hostname))
                return false;

            // Check basic format
            if (!_domainRegex.IsMatch(hostname))
                return false;

            // Check length constraints
            if (hostname.Length > 253)
                return false;

            // Check individual label lengths
            var labels = hostname.Split('.');
            foreach (var label in labels)
            {
                if (label.Length > 63 || label.Length == 0)
                    return false;
            }

            return true;
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Cleans a hostname by removing unnecessary characters and normalizing
        /// </summary>
        /// <param name="hostname">The hostname to clean</param>
        /// <returns>The cleaned hostname</returns>
        private string CleanHostname(string hostname)
        {
            // Convert to lowercase
            hostname = hostname.ToLowerInvariant();

            // Remove port numbers
            int portIndex = hostname.LastIndexOf(':');
            if (portIndex > 0 && portIndex < hostname.Length - 1)
            {
                // Check if what follows the colon is a port number
                string portPart = hostname.Substring(portIndex + 1);
                if (int.TryParse(portPart, out int port) && port > 0 && port <= 65535)
                {
                    hostname = hostname.Substring(0, portIndex);
                }
            }

            // Remove trailing dot
            hostname = hostname.TrimEnd('.');

            // Remove leading/trailing whitespace
            hostname = hostname.Trim();

            return hostname;
        }

        /// <summary>
        /// Checks if a hostname is an IP address
        /// </summary>
        /// <param name="hostname">The hostname to check</param>
        /// <returns>True if it's an IP address, false otherwise</returns>
        private bool IsIpAddress(string hostname)
        {
            return _ipv4Regex.IsMatch(hostname) || _ipv6Regex.IsMatch(hostname);
        }

        /// <summary>
        /// Checks if a hostname is a local domain
        /// </summary>
        /// <param name="hostname">The hostname to check</param>
        /// <returns>True if it's a local domain, false otherwise</returns>
        private bool IsLocalDomain(string hostname)
        {
            var localDomains = new[]
            {
                "localhost",
                "local",
                "test",
                "invalid",
                "example",
                "corp",
                "internal"
            };

            return localDomains.Any(local => 
                hostname.Equals(local, StringComparison.OrdinalIgnoreCase) ||
                hostname.EndsWith($".{local}", StringComparison.OrdinalIgnoreCase));
        }

        /// <summary>
        /// Internal method to extract the main domain from a validated hostname
        /// </summary>
        /// <param name="hostname">The validated hostname</param>
        /// <returns>The main domain</returns>
        private string ExtractMainDomainInternal(string hostname)
        {
            var parts = hostname.Split('.');

            if (parts.Length <= 2)
            {
                // Already a main domain (e.g., "example.com")
                return hostname;
            }

            // Check for common second-level domains
            string possibleSLD = string.Join(".", parts.Skip(parts.Length - 2));
            if (_commonSLDs.Contains(possibleSLD))
            {
                // Three-part domain with common SLD (e.g., "example.co.uk")
                if (parts.Length >= 3)
                {
                    return string.Join(".", parts.Skip(parts.Length - 3));
                }
                return hostname;
            }

            // Standard two-part domain (e.g., "example.com" from "www.example.com")
            return string.Join(".", parts.Skip(parts.Length - 2));
        }

        /// <summary>
        /// Disposes the domain extractor
        /// </summary>
        public void Dispose()
        {
            // Nothing to dispose for this implementation
        }

        #endregion
    }
} 