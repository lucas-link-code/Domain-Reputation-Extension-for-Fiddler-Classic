using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Data;
using System.Linq;
using System.Text;
using System.Windows.Forms;
using System.Collections.Concurrent;

#if !BUILD_WITHOUT_FIDDLER
using Fiddler;
#endif

namespace DomainReputationInspector
{
    /// <summary>
    /// User control for displaying domain reputation information
    /// </summary>
    public partial class DomainReputationUI : UserControl
    {
        #region Events

        /// <summary>
        /// Event raised when the API key is changed
        /// </summary>
        public event EventHandler<string> ApiKeyChanged;

        /// <summary>
        /// Event raised when refresh is requested for a domain
        /// </summary>
        public event EventHandler<string> RefreshRequested;

        /// <summary>
        /// Event raised when clear is requested
        /// </summary>
        public event EventHandler ClearRequested;

        /// <summary>
        /// Event raised when a domain is selected
        /// </summary>
        public event EventHandler<string> DomainSelected;

        /// <summary>
        /// Event raised when the ET Pro API key is changed
        /// </summary>
        public event EventHandler<string> ETProKeyChanged;

        #endregion

        #region Private Fields

        /// <summary>
        /// Thread-safe collection of domain rows
        /// </summary>
        private readonly ConcurrentDictionary<string, DataGridViewRow> _domainRows = new ConcurrentDictionary<string, DataGridViewRow>();

        /// <summary>
        /// Flag to prevent recursive API key change events
        /// </summary>
        private bool _updatingApiKey = false;

        /// <summary>
        /// Reference to the ET Rules service
        /// </summary>
        private EmergingThreatsRulesService _etRulesService;

        /// <summary>
        /// Flag to prevent recursive ET key change events
        /// </summary>
        private bool _updatingETKey = false;

        /// <summary>
        /// Placeholder text for ET Pro key textbox
        /// </summary>
        private const string ET_PRO_PLACEHOLDER = "Not required for ET Open rules";

        private const string VT_API_PLACEHOLDER = "Paste VirusTotal API key";

        /// <summary>
        /// Flag to track if placeholder is currently shown
        /// </summary>
        private bool _showingETProPlaceholder = false;

        private bool _showingVtPlaceholder = false;

        /// <summary>
        /// Timer to periodically refresh ET status
        /// </summary>
        private System.Windows.Forms.Timer _etStatusRefreshTimer;

        /// <summary>
        /// Reference to domain tracking for counters
        /// </summary>
        private ConcurrentDictionary<string, DomainTrackingInfo> _domainTrackingRef;

        // Cached column indices to avoid index drift after designer changes
        private int _idxDomain = -1;
        private int _idxRequests = -1;
        private int _idxApiCalls = -1;
        private int _idxETThreat = -1;
        private int _idxMalicious = -1;
        private int _idxSuspicious = -1;
        private int _idxHarmless = -1;
        private int _idxUndetected = -1;
        private int _idxStatus = -1;
        private int _idxError = -1;

        #endregion

        #region Constructor

        /// <summary>
        /// Initializes a new instance of the DomainReputationUI
        /// </summary>
        public DomainReputationUI()
        {
            InitializeComponent();
            InitializeUI();
        }

        #endregion

        #region Public Methods

        /// <summary>
        /// Adds a new domain to the list
        /// </summary>
        /// <param name="domain">The domain to add</param>
        public void AddDomain(string domain)
        {
            if (string.IsNullOrEmpty(domain))
                return;

            if (InvokeRequired)
            {
                Invoke(new Action<string>(AddDomain), domain);
                return;
            }

            if (_domainRows.ContainsKey(domain))
                return;

            // Create new row
            var row = new DataGridViewRow();
            row.CreateCells(dgvDomains);
            // Cache indices if not cached yet
            if (dgvDomains.Columns.Count > 0 && _idxDomain < 0)
            {
                InitializeColumnIndices();
            }
            row.Cells[_idxDomain].Value = domain;
            // Counters
            int requestCount = 1;
            int apiCallsMade = 0;
            if (_domainTrackingRef != null && _domainTrackingRef.TryGetValue(domain, out var track))
            {
                requestCount = track.RequestCount;
                apiCallsMade = track.ApiCallsMade;
            }
            row.Cells[_idxRequests].Value = requestCount;          // Requests
            row.Cells[_idxApiCalls].Value = apiCallsMade;          // ApiCallsMade
            // ET & VT stats
            row.Cells[_idxETThreat].Value = "";                   // ET Threat
            row.Cells[_idxMalicious].Value = "";                  // Malicious
            row.Cells[_idxSuspicious].Value = "";                 // Suspicious
            row.Cells[_idxHarmless].Value = "";                   // Harmless
            row.Cells[_idxUndetected].Value = "";                 // Undetected
            // Status and error
            row.Cells[_idxStatus].Value = "Queued";               // Status
            row.Cells[_idxError].Value = "";                      // Error
            row.Tag = domain;

            var selected = SnapshotMultiSelection();
            dgvDomains.Rows.Add(row);
            _domainRows.TryAdd(domain, row);
            RestoreMultiSelection(selected);

            UpdateStatus();
        }

        /// <summary>
        /// Updates the reputation information for a domain
        /// </summary>
        /// <param name="domain">The domain to update</param>
        /// <param name="maliciousCount">Count of malicious detections</param>
        /// <param name="suspiciousCount">Count of suspicious detections</param>
        /// <param name="harmlessCount">Count of harmless detections</param>
        /// <param name="undetectedCount">Count of undetected</param>
        /// <param name="error">Error message if any</param>
        public void UpdateDomainReputation(string domain, int maliciousCount, int suspiciousCount, int harmlessCount, int undetectedCount, string error = null)
        {
            if (string.IsNullOrEmpty(domain))
                return;

            if (InvokeRequired)
            {
                Invoke(new Action<string, int, int, int, int, string>(UpdateDomainReputation), 
                       domain, maliciousCount, suspiciousCount, harmlessCount, undetectedCount, error);
                return;
            }

            if (_domainRows.TryGetValue(domain, out var row))
            {
                var selected = SnapshotMultiSelection();
                if (!string.IsNullOrEmpty(error))
                {
                    ApplyVtQueryError(row, error);
                }
                else
                {
                    row.Cells[_idxMalicious].Value = maliciousCount.ToString();
                    row.Cells[_idxSuspicious].Value = suspiciousCount.ToString();
                    row.Cells[_idxHarmless].Value = harmlessCount.ToString();
                    row.Cells[_idxUndetected].Value = undetectedCount.ToString();
                    row.Cells[_idxStatus].Value = "Analyzed";
                    row.Cells[_idxError].Value = "";

                    if (maliciousCount > 0)
                    {
                        row.DefaultCellStyle.BackColor = Color.LightCoral;
                    }
                    else if (suspiciousCount > 0)
                    {
                        row.DefaultCellStyle.BackColor = Color.LightYellow;
                    }
                    else
                    {
                        row.DefaultCellStyle.BackColor = Color.LightGreen;
                    }
                }
                RestoreMultiSelection(selected);
            }
        }

        /// <summary>
        /// Updates the error status for a domain
        /// </summary>
        /// <param name="domain">The domain to update</param>
        /// <param name="error">The error message</param>
        public void UpdateDomainError(string domain, string error)
        {
            if (string.IsNullOrEmpty(domain))
                return;

            if (InvokeRequired)
            {
                Invoke(new Action<string, string>(UpdateDomainError), domain, error);
                return;
            }

            if (_domainRows.TryGetValue(domain, out var row))
            {
                var selected = SnapshotMultiSelection();
                ApplyVtQueryError(row, error);
                RestoreMultiSelection(selected);
            }
        }

        /// <summary>
        /// Updates counters (Requests, ApiCallsMade) for a domain
        /// </summary>
        public void UpdateDomainCounters(string domain, int requestCount, int apiCallsMade)
        {
            if (string.IsNullOrEmpty(domain))
                return;

            if (InvokeRequired)
            {
                Invoke(new Action<string, int, int>(UpdateDomainCounters), domain, requestCount, apiCallsMade);
                return;
            }

            if (_domainRows.TryGetValue(domain, out var row))
            {
                if (Equals(row.Cells[_idxRequests].Value, requestCount) &&
                    Equals(row.Cells[_idxApiCalls].Value, apiCallsMade))
                    return;

                var selected = SnapshotMultiSelection();
                row.Cells[_idxRequests].Value = requestCount;
                row.Cells[_idxApiCalls].Value = apiCallsMade;
                RestoreMultiSelection(selected);
            }
        }

        /// <summary>
        /// Clears all domains from the list
        /// </summary>
        public void ClearDomains()
        {
            if (InvokeRequired)
            {
                Invoke(new Action(ClearDomains));
                return;
            }

            dgvDomains.Rows.Clear();
            _domainRows.Clear();
            UpdateStatus();
        }

        /// <summary>
        /// Sets the VirusTotal service
        /// </summary>
        /// <param name="virusTotalService">The VirusTotal service instance</param>
        public void SetVirusTotalService(VirusTotalService virusTotalService)
        {
            // Store reference if needed for future functionality
        }

        /// <summary>
        /// Sets the domain tracking dictionary
        /// </summary>
        /// <param name="domainTracking">The domain tracking dictionary</param>
        public void SetDomainTracking(ConcurrentDictionary<string, DomainTrackingInfo> domainTracking)
        {
            _domainTrackingRef = domainTracking;
        }

        /// <summary>
        /// Sets the ET Rules service
        /// </summary>
        /// <param name="etRulesService">The ET Rules service instance</param>
        public void SetETRulesService(EmergingThreatsRulesService etRulesService)
        {
            _etRulesService = etRulesService;
            
            if (_etRulesService != null)
            {
                // Load current ET Pro key
                if (!_updatingETKey)
                {
                    _updatingETKey = true;
                    var savedKey = _etRulesService.GetETProApiKey();
                    if (!string.IsNullOrEmpty(savedKey))
                    {
                        txtETProKey.Text = savedKey;
                        txtETProKey.ForeColor = SystemColors.WindowText;
                        txtETProKey.PasswordChar = '*';
                        _showingETProPlaceholder = false;
                    }
                    else
                    {
                        // Show placeholder text when no key is saved
                        txtETProKey.Text = ET_PRO_PLACEHOLDER;
                        txtETProKey.ForeColor = SystemColors.GrayText;
                        txtETProKey.PasswordChar = '\0';
                        _showingETProPlaceholder = true;
                    }
                    _updatingETKey = false;
                }
                
                // Update status
                UpdateETStatus();
            }
        }

        /// <summary>
        /// Logs a debug message to Fiddler console
        /// </summary>
        /// <param name="message">The message to log</param>
        private void LogDebug(string message)
        {
#if !BUILD_WITHOUT_FIDDLER
            FiddlerApplication.Log.LogString("[UI-DEBUG] " + message);
#else
            System.Diagnostics.Debug.WriteLine("[UI-DEBUG] " + message);
#endif
        }

        /// <summary>
        /// Refreshes the ET Rules status line
        /// </summary>
        public void RefreshETStatus()
        {
            if (InvokeRequired)
            {
                Invoke(new Action(RefreshETStatus));
                return;
            }
            
            UpdateETStatus();
        }

        /// <summary>
        /// Updates ET information for a domain
        /// </summary>
        /// <param name="domain">The domain to update</param>
        /// <param name="etInfo">ET information</param>
        public void UpdateETInformation(string domain, ETDomainInfo etInfo)
        {
            if (string.IsNullOrEmpty(domain) || etInfo == null)
                return;

            if (InvokeRequired)
            {
                Invoke(new Action<string, ETDomainInfo>(UpdateETInformation), domain, etInfo);
                return;
            }

            if (_domainRows.TryGetValue(domain, out var row))
            {
                var selected = SnapshotMultiSelection();
                row.Cells[_idxETThreat].Value = $"{etInfo.Severity.ToUpper()}: {etInfo.Description}";

                switch (etInfo.Severity.ToLower())
                {
                    case "high":
                        row.Cells[_idxETThreat].Style.BackColor = Color.Red;
                        row.Cells[_idxETThreat].Style.ForeColor = Color.White;
                        break;
                    case "medium":
                        row.Cells[_idxETThreat].Style.BackColor = Color.Orange;
                        row.Cells[_idxETThreat].Style.ForeColor = Color.Black;
                        break;
                    case "low":
                        row.Cells[_idxETThreat].Style.BackColor = Color.Yellow;
                        row.Cells[_idxETThreat].Style.ForeColor = Color.Black;
                        break;
                }
                RestoreMultiSelection(selected);
            }
        }

        #endregion

        #region Private Methods

        /// <summary>
        /// Initializes the UI components
        /// </summary>
        private void InitializeUI()
        {
            // Configure DataGridView
            dgvDomains.AutoSizeColumnsMode = DataGridViewAutoSizeColumnsMode.Fill;
            dgvDomains.SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            dgvDomains.MultiSelect = true;
            dgvDomains.ReadOnly = true;
            dgvDomains.AllowUserToAddRows = false;
            dgvDomains.AllowUserToDeleteRows = false;
            dgvDomains.EditMode = DataGridViewEditMode.EditProgrammatically;
            dgvDomains.BorderStyle = BorderStyle.FixedSingle;

            // Ensure ET Threat column exists and is positioned after ApiCallsMade
            var existingEtCol = dgvDomains.Columns["colETThreat"];
            if (existingEtCol == null)
            {
                var etColumn = new DataGridViewTextBoxColumn
                {
                    Name = "colETThreat",
                    HeaderText = "ET Threat",
                    FillWeight = 20
                };
                // Insert at index 3 (after ApiCallsMade)
                dgvDomains.Columns.Insert(3, etColumn);
            }
            else if (existingEtCol.Index != 3)
            {
                dgvDomains.Columns.Remove(existingEtCol);
                dgvDomains.Columns.Insert(3, existingEtCol);
            }

            // Set up columns (by name to avoid index drift)
            dgvDomains.Columns["colDomain"].FillWeight = 30;
            dgvDomains.Columns["colRequests"].FillWeight = 10;
            dgvDomains.Columns["colApiCallsMade"].FillWeight = 10;
            dgvDomains.Columns["colETThreat"].FillWeight = 20;
            dgvDomains.Columns["colMalicious"].FillWeight = 10;
            dgvDomains.Columns["colSuspicious"].FillWeight = 10;
            dgvDomains.Columns["colHarmless"].FillWeight = 10;
            dgvDomains.Columns["colUndetected"].FillWeight = 10;
            dgvDomains.Columns["colStatus"].FillWeight = 10;
            dgvDomains.Columns["colError"].FillWeight = 20;

            // Configure API key textbox
            txtApiKey.PasswordChar = '*';
            txtApiKey.UseSystemPasswordChar = true;

            ApplyPublicVtKeyLayout();

            // Cache column indices now that columns exist
            InitializeColumnIndices();

            // Set initial status
            UpdateStatus();
        }

        /// <summary>
        /// Updates the status label
        /// </summary>
        private void UpdateStatus()
        {
            int totalDomains = _domainRows.Count;
            int maliciousDomains = 0;
            int suspiciousDomains = 0;

            foreach (DataGridViewRow row in dgvDomains.Rows)
            {
                if (row.Cells[_idxMalicious].Value != null && int.TryParse(row.Cells[_idxMalicious].Value.ToString(), out int malicious) && malicious > 0)
                    maliciousDomains++;
                else if (row.Cells[_idxSuspicious].Value != null && int.TryParse(row.Cells[_idxSuspicious].Value.ToString(), out int suspicious) && suspicious > 0)
                    suspiciousDomains++;
            }

            lblStatus.Text = $"Domains: {totalDomains} | Malicious: {maliciousDomains} | Suspicious: {suspiciousDomains}";
        }

        private void ApplyPublicVtKeyLayout()
        {
#if PUBLIC_RELEASE
            lblApiKey.Visible = true;
            txtApiKey.Visible = true;
            btnSave.Visible = true;

            lblInstructions.Text = "Paste a VirusTotal API key to query domain reports. ET Pro is optional.";

            lblApiKey.Location = new System.Drawing.Point(10, 28);
            txtApiKey.Location = new System.Drawing.Point(75, 25);
            btnSave.Location = new System.Drawing.Point(525, 24);

            lblETProKey.Location = new System.Drawing.Point(10, 54);
            txtETProKey.Location = new System.Drawing.Point(75, 51);
            btnSaveETKey.Location = new System.Drawing.Point(525, 50);

            lblETStatus.Location = new System.Drawing.Point(10, 76);

            btnCopy.Location = new System.Drawing.Point(10, 98);
            btnUpdateET.Location = new System.Drawing.Point(105, 98);
            btnRefresh.Location = new System.Drawing.Point(450, 98);
            btnClear.Location = new System.Drawing.Point(525, 98);

            pnlControls.Height = 128;
#endif
        }

        private void ShowVtPlaceholder()
        {
            _updatingApiKey = true;
            _showingVtPlaceholder = true;
            txtApiKey.UseSystemPasswordChar = false;
            txtApiKey.PasswordChar = '\0';
            txtApiKey.Text = VT_API_PLACEHOLDER;
            txtApiKey.ForeColor = SystemColors.GrayText;
            _updatingApiKey = false;
        }

        private void HideVtPlaceholderForEdit()
        {
            _updatingApiKey = true;
            _showingVtPlaceholder = false;
            txtApiKey.Text = "";
            txtApiKey.ForeColor = SystemColors.WindowText;
            txtApiKey.PasswordChar = '*';
            txtApiKey.UseSystemPasswordChar = true;
            _updatingApiKey = false;
        }

        private string GetEnteredVtApiKey()
        {
            if (_showingVtPlaceholder)
                return "";
            return txtApiKey.Text ?? "";
        }

        private void ApplyVtQueryError(DataGridViewRow row, string error)
        {
            if (_idxDomain < 0)
                InitializeColumnIndices();

            if (_idxStatus >= 0 && _idxStatus < row.Cells.Count)
                row.Cells[_idxStatus].Value = "Error";
            if (_idxError >= 0 && _idxError < row.Cells.Count)
                row.Cells[_idxError].Value = error;
            if (_idxMalicious >= 0 && _idxMalicious < row.Cells.Count)
                row.Cells[_idxMalicious].Value = "";
            if (_idxSuspicious >= 0 && _idxSuspicious < row.Cells.Count)
                row.Cells[_idxSuspicious].Value = "";
            if (_idxHarmless >= 0 && _idxHarmless < row.Cells.Count)
                row.Cells[_idxHarmless].Value = "";
            if (_idxUndetected >= 0 && _idxUndetected < row.Cells.Count)
                row.Cells[_idxUndetected].Value = "";

            row.DefaultCellStyle.BackColor = Color.LightGray;
        }

        #endregion

        #region Event Handlers

        /// <summary>
        /// Handles the API key text changed event
        /// </summary>
        private void txtApiKey_TextChanged(object sender, EventArgs e)
        {
        }

        /// <summary>
        /// Handles the save button click event
        /// </summary>
        private void btnSave_Click(object sender, EventArgs e)
        {
            var keyToSave = GetEnteredVtApiKey();
            if (string.IsNullOrEmpty(keyToSave))
            {
                MessageBox.Show("Enter a VirusTotal API key before saving.", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
                return;
            }

            Properties.Settings.Default.ApiKey = keyToSave;
            Properties.Settings.Default.Save();
            ApiKeyChanged?.Invoke(this, keyToSave);
            btnRefresh_Click(this, EventArgs.Empty);
            MessageBox.Show("API key saved successfully!", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
        }

        private void txtApiKey_Enter(object sender, EventArgs e)
        {
            if (_showingVtPlaceholder)
            {
                HideVtPlaceholderForEdit();
            }
        }

        private void txtApiKey_Leave(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(txtApiKey.Text) && !_updatingApiKey)
            {
                ShowVtPlaceholder();
            }
        }

        /// <summary>
        /// Handles the refresh button click event
        /// </summary>
        private void btnRefresh_Click(object sender, EventArgs e)
        {
            try
            {
                LogDebug("REFRESH BUTTON: Starting refresh of ALL domains");
                
                // Always refresh ALL domains when refresh button is clicked
                foreach (DataGridViewRow row in dgvDomains.Rows)
                {
                    var domain = row.Tag?.ToString();
                    if (!string.IsNullOrEmpty(domain))
                    {
                        // Ensure column indices are initialized
                        if (_idxDomain < 0) { InitializeColumnIndices(); }
                        
                        // Clear VT data and set to Queued
                        if (_idxMalicious >= 0 && _idxMalicious < row.Cells.Count)
                            row.Cells[_idxMalicious].Value = "";
                        if (_idxSuspicious >= 0 && _idxSuspicious < row.Cells.Count)
                            row.Cells[_idxSuspicious].Value = "";
                        if (_idxHarmless >= 0 && _idxHarmless < row.Cells.Count)
                            row.Cells[_idxHarmless].Value = "";
                        if (_idxUndetected >= 0 && _idxUndetected < row.Cells.Count)
                            row.Cells[_idxUndetected].Value = "";
                        if (_idxStatus >= 0 && _idxStatus < row.Cells.Count)
                            row.Cells[_idxStatus].Value = "Queued";
                        if (_idxError >= 0 && _idxError < row.Cells.Count)
                            row.Cells[_idxError].Value = "";
                        row.DefaultCellStyle.BackColor = Color.White;
                        
                        LogDebug($"REFRESH ALL: Set {domain} to Queued status (Status idx: {_idxStatus})");
                        RefreshRequested?.Invoke(this, domain);
                    }
                }
                
                LogDebug($"REFRESH BUTTON: Completed refresh request for {dgvDomains.Rows.Count} domains");
            }
            catch (Exception ex)
            {
                LogDebug($"REFRESH BUTTON ERROR: {ex.Message}");
            }
        }

        /// <summary>
        /// Handles the clear button click event
        /// </summary>
        private void btnClear_Click(object sender, EventArgs e)
        {
            ClearRequested?.Invoke(this, EventArgs.Empty);
        }

        /// <summary>
        /// Copies analyzed domain list (single-column plaintext) to clipboard
        /// </summary>
        private void btnCopy_Click(object sender, EventArgs e)
        {
            try
            {
                var domains = new List<string>();
                foreach (DataGridViewRow row in dgvDomains.Rows)
                {
                    var status = row.Cells[_idxStatus].Value?.ToString();
                    if (string.Equals(status, "Analyzed", StringComparison.OrdinalIgnoreCase))
                    {
                        var domain = row.Cells[_idxDomain].Value?.ToString();
                        if (!string.IsNullOrEmpty(domain))
                        {
                            domains.Add(domain);
                        }
                    }
                }

                if (domains.Count > 0)
                {
                    Clipboard.SetText(string.Join("\r\n", domains));
                    MessageBox.Show($"Copied {domains.Count} domains to clipboard.", "Copied", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
                else
                {
                    MessageBox.Show("No analyzed domains to copy.", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Copy failed: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// Copies Domain column values from selected rows
        /// </summary>
        private void menuCopySelectedDomains_Click(object sender, EventArgs e)
        {
            try
            {
                var selectedRows = dgvDomains.SelectedRows;
                if (selectedRows.Count == 0)
                {
                    MessageBox.Show("No rows selected.", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }

                // Ensure column indices are initialized
                if (_idxDomain < 0) { InitializeColumnIndices(); }

                var domains = new List<string>();
                foreach (DataGridViewRow row in selectedRows)
                {
                    var domain = row.Cells[_idxDomain].Value?.ToString();
                    if (!string.IsNullOrEmpty(domain))
                    {
                        domains.Add(domain);
                    }
                }

                if (domains.Count > 0)
                {
                    Clipboard.SetText(string.Join("\r\n", domains));
                    MessageBox.Show($"Copied {domains.Count} domain(s) to clipboard.", "Copied", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Copy failed: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// Copies ET Threat column values from selected rows
        /// </summary>
        private void menuCopySelectedETThreats_Click(object sender, EventArgs e)
        {
            try
            {
                var selectedRows = dgvDomains.SelectedRows;
                if (selectedRows.Count == 0)
                {
                    MessageBox.Show("No rows selected.", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }

                // Ensure column indices are initialized
                if (_idxDomain < 0) { InitializeColumnIndices(); }

                var threats = new List<string>();
                foreach (DataGridViewRow row in selectedRows)
                {
                    var domain = row.Cells[_idxDomain].Value?.ToString();
                    var threat = row.Cells[_idxETThreat].Value?.ToString();
                    if (!string.IsNullOrEmpty(domain))
                    {
                        var entry = string.IsNullOrEmpty(threat) 
                            ? $"{domain}: (No ET threat)" 
                            : $"{domain}: {threat}";
                        threats.Add(entry);
                    }
                }

                if (threats.Count > 0)
                {
                    Clipboard.SetText(string.Join("\r\n", threats));
                    MessageBox.Show($"Copied {threats.Count} ET threat entry(ies) to clipboard.", "Copied", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Copy failed: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// Copies values from selected cells (copies all selected cell values)
        /// </summary>
        private void menuCopySelectedCells_Click(object sender, EventArgs e)
        {
            try
            {
                var selectedCells = dgvDomains.SelectedCells;
                if (selectedCells.Count == 0)
                {
                    MessageBox.Show("No cells selected.", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }

                // Sort cells by row index, then by column index for consistent output
                var sortedCells = new List<DataGridViewCell>();
                foreach (DataGridViewCell cell in selectedCells)
                {
                    sortedCells.Add(cell);
                }
                sortedCells.Sort((a, b) => 
                {
                    int rowCompare = a.RowIndex.CompareTo(b.RowIndex);
                    if (rowCompare != 0) return rowCompare;
                    return a.ColumnIndex.CompareTo(b.ColumnIndex);
                });

                var cellValues = new List<string>();
                
                // Copy all selected cells with their values
                foreach (var cell in sortedCells)
                {
                    var columnName = dgvDomains.Columns[cell.ColumnIndex].HeaderText;
                    var value = cell.Value?.ToString() ?? "";
                    
                    // Format as "ColumnName: Value" for clarity
                    cellValues.Add($"{columnName}: {value}");
                }

                if (cellValues.Count > 0)
                {
                    Clipboard.SetText(string.Join("\r\n", cellValues));
                    MessageBox.Show($"Copied {cellValues.Count} cell value(s) to clipboard.", "Copied", MessageBoxButtons.OK, MessageBoxIcon.Information);
                }
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Copy failed: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// Copies entire selected rows as tab-delimited text
        /// </summary>
        private void menuCopySelectedRows_Click(object sender, EventArgs e)
        {
            try
            {
                var selectedRows = dgvDomains.SelectedRows;
                if (selectedRows.Count == 0)
                {
                    MessageBox.Show("No rows selected.", "Info", MessageBoxButtons.OK, MessageBoxIcon.Information);
                    return;
                }

                var sb = new StringBuilder();
                
                // Add header row
                var headers = new List<string>();
                foreach (DataGridViewColumn col in dgvDomains.Columns)
                {
                    headers.Add(col.HeaderText);
                }
                sb.AppendLine(string.Join("\t", headers));

                // Add data rows
                foreach (DataGridViewRow row in selectedRows)
                {
                    var values = new List<string>();
                    foreach (DataGridViewCell cell in row.Cells)
                    {
                        values.Add(cell.Value?.ToString() ?? "");
                    }
                    sb.AppendLine(string.Join("\t", values));
                }

                Clipboard.SetText(sb.ToString());
                MessageBox.Show($"Copied {selectedRows.Count} row(s) to clipboard (tab-delimited).", "Copied", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Copy failed: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// Handles the Update ET button click event
        /// </summary>
        private void btnUpdateET_Click(object sender, EventArgs e)
        {
            try
            {
                LogDebug("UPDATE ET BUTTON: Force update requested by user");
                
                // Disable button to prevent multiple simultaneous updates
                btnUpdateET.Enabled = false;
                btnUpdateET.Text = "Updating...";
                
                // Update status to show update in progress
                if (_etRulesService != null)
                {
                    // Trigger async update without blocking UI
                    System.Threading.Tasks.Task.Run(async () =>
                    {
                        try
                        {
                            LogDebug("UPDATE ET: Starting force update process");
                            await _etRulesService.ForceUpdateAsync();
                            LogDebug("UPDATE ET: Force update completed successfully");
                            
                            // Update UI on main thread
                            this.BeginInvoke(new Action(() =>
                            {
                                btnUpdateET.Enabled = true;
                                btnUpdateET.Text = "Update ET";
                                UpdateETStatus(); // Refresh the status line
                                MessageBox.Show("ET Rules updated successfully!", "Update Complete", MessageBoxButtons.OK, MessageBoxIcon.Information);
                            }));
                        }
                        catch (Exception ex)
                        {
                            LogDebug($"UPDATE ET ERROR: {ex.Message}");
                            
                            // Update UI on main thread with error
                            this.BeginInvoke(new Action(() =>
                            {
                                btnUpdateET.Enabled = true;
                                btnUpdateET.Text = "Update ET";
                                MessageBox.Show($"ET Rules update failed: {ex.Message}", "Update Failed", MessageBoxButtons.OK, MessageBoxIcon.Error);
                            }));
                        }
                    });
                }
                else
                {
                    // Re-enable button if no service available
                    btnUpdateET.Enabled = true;
                    btnUpdateET.Text = "Update ET";
                    MessageBox.Show("ET Rules service not available.", "Error", MessageBoxButtons.OK, MessageBoxIcon.Warning);
                }
            }
            catch (Exception ex)
            {
                LogDebug($"UPDATE ET BUTTON ERROR: {ex.Message}");
                
                // Ensure button is re-enabled on any error
                btnUpdateET.Enabled = true;
                btnUpdateET.Text = "Update ET";
                MessageBox.Show($"Update request failed: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// Handles the domain grid cell double-click event
        /// </summary>
        private void dgvDomains_CellDoubleClick(object sender, DataGridViewCellEventArgs e)
        {
            if (e.RowIndex >= 0 && e.RowIndex < dgvDomains.Rows.Count)
            {
                string domain = dgvDomains.Rows[e.RowIndex].Tag?.ToString();
                if (!string.IsNullOrEmpty(domain))
                {
                    DomainSelected?.Invoke(this, domain);
                }
            }
        }

        /// <summary>
        /// Handles the load event to restore API key
        /// </summary>
        private void DomainReputationUI_Load(object sender, EventArgs e)
        {
#if PUBLIC_RELEASE
            _updatingApiKey = true;
            try
            {
                var savedKey = Properties.Settings.Default.ApiKey ?? "";
                if (!string.IsNullOrEmpty(savedKey))
                {
                    _showingVtPlaceholder = false;
                    txtApiKey.Text = savedKey;
                    txtApiKey.ForeColor = SystemColors.WindowText;
                    txtApiKey.PasswordChar = '*';
                    txtApiKey.UseSystemPasswordChar = true;
                }
                else
                {
                    ShowVtPlaceholder();
                }
            }
            finally
            {
                _updatingApiKey = false;
            }

            var enteredKey = GetEnteredVtApiKey();
            if (!string.IsNullOrEmpty(enteredKey))
            {
                ApiKeyChanged?.Invoke(this, enteredKey);
            }
#endif

            // ET Pro key is optional; value will be populated by SetETRulesService if available
            _updatingETKey = false;

            // Initialize ET Pro placeholder if no service has been set yet
            if (_etRulesService == null && string.IsNullOrEmpty(txtETProKey.Text))
            {
                _updatingETKey = true;
                txtETProKey.Text = ET_PRO_PLACEHOLDER;
                txtETProKey.ForeColor = SystemColors.GrayText;
                txtETProKey.PasswordChar = '\0';
                _showingETProPlaceholder = true;
                _updatingETKey = false;
            }

            // Update ET status
            UpdateETStatus();
            InitializeColumnIndices();
            
            // Initialize ET status refresh timer
            _etStatusRefreshTimer = new System.Windows.Forms.Timer();
            _etStatusRefreshTimer.Interval = 5000; // Refresh every 5 seconds
            _etStatusRefreshTimer.Tick += (s, evt) => UpdateETStatus();
            _etStatusRefreshTimer.Start();
            
            // Clean up timer when form is disposed
            this.HandleDestroyed += (s, evt) => {
                _etStatusRefreshTimer?.Stop();
                _etStatusRefreshTimer?.Dispose();
            };
        }

        /// <summary>
        /// Handles the ET Pro key text changed event
        /// </summary>
        private void txtETProKey_TextChanged(object sender, EventArgs e)
        {
            if (!_updatingETKey && !_showingETProPlaceholder)
            {
                ETProKeyChanged?.Invoke(this, txtETProKey.Text);
                UpdateETStatus();
            }
        }

        /// <summary>
        /// Handles the ET Pro key textbox Enter event (focus gained)
        /// </summary>
        private void txtETProKey_Enter(object sender, EventArgs e)
        {
            if (_showingETProPlaceholder)
            {
                _updatingETKey = true;
                txtETProKey.Text = "";
                txtETProKey.ForeColor = SystemColors.WindowText;
                txtETProKey.PasswordChar = '*';
                _showingETProPlaceholder = false;
                _updatingETKey = false;
            }
        }

        /// <summary>
        /// Handles the ET Pro key textbox Leave event (focus lost)
        /// </summary>
        private void txtETProKey_Leave(object sender, EventArgs e)
        {
            if (string.IsNullOrEmpty(txtETProKey.Text) && !_updatingETKey)
            {
                _updatingETKey = true;
                _showingETProPlaceholder = true;
                txtETProKey.Text = ET_PRO_PLACEHOLDER;
                txtETProKey.ForeColor = SystemColors.GrayText;
                txtETProKey.PasswordChar = '\0'; // Show placeholder text clearly
                _updatingETKey = false;
            }
        }

        /// <summary>
        /// Handles the save ET Pro key button click event
        /// </summary>
        private void btnSaveETKey_Click(object sender, EventArgs e)
        {
            try
            {
                // Update ET Rules service (persists internally in ET settings store)
                // Don't save the placeholder text as the actual key
                var keyToSave = _showingETProPlaceholder ? "" : txtETProKey.Text;
                _etRulesService?.SetETProApiKey(keyToSave);

                // Update status
                UpdateETStatus();

                // Trigger immediate rules update so new data appears right away
                var svc = _etRulesService;
                if (svc != null)
                {
                    System.Threading.Tasks.Task.Run(async () =>
                    {
                        try
                        {
                            await svc.ForceUpdateAsync();
                            this.BeginInvoke(new Action(UpdateETStatus));
                        }
                        catch { }
                    });
                }

                var hasRealKey = !string.IsNullOrEmpty(txtETProKey.Text) && !_showingETProPlaceholder;
                var keyType = hasRealKey ? "ET Pro (commercial)" : "ET Open (free)";
                MessageBox.Show($"ET key saved successfully!\nUsing: {keyType}", "Success", MessageBoxButtons.OK, MessageBoxIcon.Information);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"Error saving ET key: {ex.Message}", "Error", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        /// <summary>
        /// Updates the ET status label
        /// </summary>
        private void UpdateETStatus()
        {
            try
            {
                var hasRealKey = !string.IsNullOrEmpty(txtETProKey.Text) && !_showingETProPlaceholder;
                
                if (_etRulesService != null)
                {
                    lblETStatus.Text = _etRulesService.GetStatistics();
                }
                else
                {
                    var keyType = hasRealKey ? "ET Pro (commercial)" : "ET Open (free)";
                    lblETStatus.Text = $"ET Rules: Using {keyType} - Service not initialized";
                }

                lblETStatus.ForeColor = hasRealKey ? Color.DarkGreen : Color.DarkBlue;
            }
            catch (Exception ex)
            {
                lblETStatus.Text = $"ET Rules: Error - {ex.Message}";
                lblETStatus.ForeColor = Color.Red;
            }
        }

        private void InitializeColumnIndices()
        {
            try
            {
                if (dgvDomains == null || dgvDomains.Columns == null || dgvDomains.Columns.Count == 0)
                    return;

                _idxDomain = GetIndex("colDomain");
                _idxRequests = GetIndex("colRequests");
                _idxApiCalls = GetIndex("colApiCallsMade");
                _idxETThreat = GetIndex("colETThreat");
                _idxMalicious = GetIndex("colMalicious");
                _idxSuspicious = GetIndex("colSuspicious");
                _idxHarmless = GetIndex("colHarmless");
                _idxUndetected = GetIndex("colUndetected");
                _idxStatus = GetIndex("colStatus");
                _idxError = GetIndex("colError");
            }
            catch
            {
                // Ignore; will retry later
            }
        }

        private int GetIndex(string columnName)
        {
            var col = dgvDomains.Columns[columnName];
            return col != null ? col.Index : -1;
        }

        private int[] SnapshotMultiSelection()
        {
            int count = dgvDomains.SelectedRows.Count;
            if (count <= 1)
                return null;

            var rows = new int[count];
            for (int i = 0; i < count; i++)
                rows[i] = dgvDomains.SelectedRows[i].Index;
            return rows;
        }

        private void RestoreMultiSelection(int[] rows)
        {
            if (rows == null || rows.Length == 0)
                return;

            dgvDomains.ClearSelection();
            for (int i = 0; i < rows.Length; i++)
            {
                int idx = rows[i];
                if (idx >= 0 && idx < dgvDomains.Rows.Count)
                    dgvDomains.Rows[idx].Selected = true;
            }
        }

        #endregion
    }

    internal sealed class RowSelectDataGridView : DataGridView
    {
        private int _anchorRow;
        private int _dragStartRow = -1;

        public RowSelectDataGridView()
        {
            MultiSelect = true;
            SelectionMode = DataGridViewSelectionMode.FullRowSelect;
            EditMode = DataGridViewEditMode.EditProgrammatically;
        }

        protected override void OnMouseDown(MouseEventArgs e)
        {
            HitTestInfo ht = HitTest(e.X, e.Y);
            if (ht.Type == DataGridViewHitTestType.Cell && ht.RowIndex >= 0)
            {
                if (e.Button == MouseButtons.Right)
                {
                    if (!Rows[ht.RowIndex].Selected)
                    {
                        ClearSelection();
                        Rows[ht.RowIndex].Selected = true;
                        _anchorRow = ht.RowIndex;
                    }
                    SetCurrentCellKeepSelection(ht.RowIndex, ht.ColumnIndex);
                    return;
                }

                if (e.Button == MouseButtons.Left)
                {
                    bool shift = (ModifierKeys & Keys.Shift) == Keys.Shift;
                    bool ctrl = (ModifierKeys & Keys.Control) == Keys.Control;

                    if (shift)
                    {
                        SelectRowRange(_anchorRow, ht.RowIndex, ctrl);
                        SetCurrentCellKeepSelection(ht.RowIndex, ht.ColumnIndex);
                        return;
                    }

                    if (ctrl)
                    {
                        Rows[ht.RowIndex].Selected = !Rows[ht.RowIndex].Selected;
                        if (Rows[ht.RowIndex].Selected)
                            SetCurrentCellKeepSelection(ht.RowIndex, ht.ColumnIndex);
                        _anchorRow = ht.RowIndex;
                        return;
                    }

                    _anchorRow = ht.RowIndex;
                    _dragStartRow = ht.RowIndex;
                }
            }

            base.OnMouseDown(e);

            if (e.Button == MouseButtons.Left && ht.RowIndex >= 0)
                _anchorRow = ht.RowIndex;
        }

        protected override void OnMouseMove(MouseEventArgs e)
        {
            base.OnMouseMove(e);

            if (_dragStartRow < 0 || (e.Button & MouseButtons.Left) == 0)
                return;
            if ((ModifierKeys & Keys.Shift) == Keys.Shift || (ModifierKeys & Keys.Control) == Keys.Control)
                return;

            HitTestInfo ht = HitTest(e.X, e.Y);
            if (ht.RowIndex >= 0)
                SelectRowRange(_dragStartRow, ht.RowIndex, false);
        }

        protected override void OnMouseUp(MouseEventArgs e)
        {
            _dragStartRow = -1;
            base.OnMouseUp(e);
        }

        private void SelectRowRange(int fromRow, int toRow, bool additive)
        {
            if (Rows.Count == 0)
                return;

            if (fromRow < 0)
                fromRow = toRow;
            fromRow = Math.Max(0, Math.Min(fromRow, Rows.Count - 1));
            toRow = Math.Max(0, Math.Min(toRow, Rows.Count - 1));

            int start = Math.Min(fromRow, toRow);
            int end = Math.Max(fromRow, toRow);

            if (!additive)
                ClearSelection();

            for (int i = start; i <= end; i++)
                Rows[i].Selected = true;
        }

        private void SetCurrentCellKeepSelection(int rowIndex, int columnIndex)
        {
            int selectedCount = SelectedRows.Count;
            int[] selected = null;
            if (selectedCount > 0)
            {
                selected = new int[selectedCount];
                for (int i = 0; i < selectedCount; i++)
                    selected[i] = SelectedRows[i].Index;
            }

            SetCurrentCell(rowIndex, columnIndex);

            if (selected == null)
                return;

            for (int i = 0; i < selected.Length; i++)
            {
                int idx = selected[i];
                if (idx >= 0 && idx < Rows.Count)
                    Rows[idx].Selected = true;
            }
        }

        private void SetCurrentCell(int rowIndex, int columnIndex)
        {
            if (columnIndex < 0)
                columnIndex = 0;
            if (rowIndex < 0 || rowIndex >= Rows.Count || columnIndex >= Columns.Count)
                return;
            if (!Rows[rowIndex].Cells[columnIndex].Visible)
                return;

            try
            {
                CurrentCell = Rows[rowIndex].Cells[columnIndex];
            }
            catch
            {
            }
        }
    }
} 