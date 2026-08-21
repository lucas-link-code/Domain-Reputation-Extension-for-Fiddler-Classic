namespace DomainReputationInspector
{
    partial class DomainReputationUI
    {
        /// <summary> 
        /// Required designer variable.
        /// </summary>
        private System.ComponentModel.IContainer components = null;

        /// <summary> 
        /// Clean up any resources being used.
        /// </summary>
        /// <param name="disposing">true if managed resources should be disposed; otherwise, false.</param>
        protected override void Dispose(bool disposing)
        {
            if (disposing && (components != null))
            {
                components.Dispose();
            }
            base.Dispose(disposing);
        }

        #region Component Designer generated code

        /// <summary> 
        /// Required method for Designer support - do not modify 
        /// the contents of this method with the code editor.
        /// </summary>
        private void InitializeComponent()
        {
            this.dgvDomains = new RowSelectDataGridView();
            this.colDomain = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.colRequests = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.colApiCallsMade = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.colETThreat = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.colMalicious = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.colSuspicious = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.colHarmless = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.colUndetected = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.colStatus = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.colError = new System.Windows.Forms.DataGridViewTextBoxColumn();
            this.contextMenuGrid = new System.Windows.Forms.ContextMenuStrip();
            this.menuCopySelectedDomains = new System.Windows.Forms.ToolStripMenuItem();
            this.menuCopySelectedETThreats = new System.Windows.Forms.ToolStripMenuItem();
            this.menuSeparator1 = new System.Windows.Forms.ToolStripSeparator();
            this.menuCopySelectedCells = new System.Windows.Forms.ToolStripMenuItem();
            this.menuCopySelectedRows = new System.Windows.Forms.ToolStripMenuItem();
            this.pnlControls = new System.Windows.Forms.Panel();
            this.btnCopy = new System.Windows.Forms.Button();
            this.btnUpdateET = new System.Windows.Forms.Button();
            this.btnClear = new System.Windows.Forms.Button();
            this.btnRefresh = new System.Windows.Forms.Button();
            this.btnSave = new System.Windows.Forms.Button();
            this.txtApiKey = new System.Windows.Forms.TextBox();
            this.lblApiKey = new System.Windows.Forms.Label();
            this.lblStatus = new System.Windows.Forms.Label();
            this.pnlMain = new System.Windows.Forms.Panel();
            this.lblInstructions = new System.Windows.Forms.Label();
            this.txtETProKey = new System.Windows.Forms.TextBox();
            this.lblETProKey = new System.Windows.Forms.Label();
            this.btnSaveETKey = new System.Windows.Forms.Button();
            this.lblETStatus = new System.Windows.Forms.Label();
            ((System.ComponentModel.ISupportInitialize)(this.dgvDomains)).BeginInit();
            this.pnlControls.SuspendLayout();
            this.pnlMain.SuspendLayout();
            this.SuspendLayout();
            // 
            // dgvDomains
            // 
            this.dgvDomains.AllowUserToAddRows = false;
            this.dgvDomains.AllowUserToDeleteRows = false;
            this.dgvDomains.BackgroundColor = System.Drawing.SystemColors.Window;
            this.dgvDomains.BorderStyle = System.Windows.Forms.BorderStyle.FixedSingle;
            this.dgvDomains.ColumnHeadersHeightSizeMode = System.Windows.Forms.DataGridViewColumnHeadersHeightSizeMode.AutoSize;
            this.dgvDomains.Columns.AddRange(new System.Windows.Forms.DataGridViewColumn[] {
            this.colDomain,
            this.colRequests,
            this.colApiCallsMade,
            this.colETThreat,
            this.colMalicious,
            this.colSuspicious,
            this.colHarmless,
            this.colUndetected,
            this.colStatus,
            this.colError});
            this.dgvDomains.Dock = System.Windows.Forms.DockStyle.Fill;
            this.dgvDomains.Location = new System.Drawing.Point(0, 105);
            this.dgvDomains.MultiSelect = true;
            this.dgvDomains.Name = "dgvDomains";
            this.dgvDomains.ReadOnly = true;
            this.dgvDomains.RowHeadersVisible = false;
            this.dgvDomains.SelectionMode = System.Windows.Forms.DataGridViewSelectionMode.FullRowSelect;
            this.dgvDomains.Size = new System.Drawing.Size(600, 320);
            this.dgvDomains.TabIndex = 0;
            this.dgvDomains.ContextMenuStrip = this.contextMenuGrid;
            this.dgvDomains.CellDoubleClick += new System.Windows.Forms.DataGridViewCellEventHandler(this.dgvDomains_CellDoubleClick);
            // 
            // contextMenuGrid
            // 
            this.contextMenuGrid.Items.AddRange(new System.Windows.Forms.ToolStripItem[] {
            this.menuCopySelectedDomains,
            this.menuCopySelectedETThreats,
            this.menuSeparator1,
            this.menuCopySelectedCells,
            this.menuCopySelectedRows});
            this.contextMenuGrid.Name = "contextMenuGrid";
            this.contextMenuGrid.Size = new System.Drawing.Size(250, 120);
            // 
            // menuCopySelectedDomains
            // 
            this.menuCopySelectedDomains.Name = "menuCopySelectedDomains";
            this.menuCopySelectedDomains.Size = new System.Drawing.Size(249, 22);
            this.menuCopySelectedDomains.Text = "Copy Selected Domains";
            this.menuCopySelectedDomains.Click += new System.EventHandler(this.menuCopySelectedDomains_Click);
            // 
            // menuCopySelectedETThreats
            // 
            this.menuCopySelectedETThreats.Name = "menuCopySelectedETThreats";
            this.menuCopySelectedETThreats.Size = new System.Drawing.Size(249, 22);
            this.menuCopySelectedETThreats.Text = "Copy Selected ET Threats";
            this.menuCopySelectedETThreats.Click += new System.EventHandler(this.menuCopySelectedETThreats_Click);
            // 
            // menuSeparator1
            // 
            this.menuSeparator1.Name = "menuSeparator1";
            this.menuSeparator1.Size = new System.Drawing.Size(246, 6);
            // 
            // menuCopySelectedCells
            // 
            this.menuCopySelectedCells.Name = "menuCopySelectedCells";
            this.menuCopySelectedCells.Size = new System.Drawing.Size(249, 22);
            this.menuCopySelectedCells.Text = "Copy Selected Cell Values";
            this.menuCopySelectedCells.Click += new System.EventHandler(this.menuCopySelectedCells_Click);
            // 
            // menuCopySelectedRows
            // 
            this.menuCopySelectedRows.Name = "menuCopySelectedRows";
            this.menuCopySelectedRows.Size = new System.Drawing.Size(249, 22);
            this.menuCopySelectedRows.Text = "Copy Selected Rows (Tab-delimited)";
            this.menuCopySelectedRows.Click += new System.EventHandler(this.menuCopySelectedRows_Click);
            // 
            // colDomain
            // 
            this.colDomain.HeaderText = "Domain";
            this.colDomain.Name = "colDomain";
            this.colDomain.ReadOnly = true;
            this.colDomain.Width = 200;
            // 
            // colRequests
            // 
            this.colRequests.HeaderText = "Requests";
            this.colRequests.Name = "colRequests";
            this.colRequests.ReadOnly = true;
            this.colRequests.Width = 60;
            // 
            // colApiCallsMade
            // 
            this.colApiCallsMade.HeaderText = "ApiCallsMade";
            this.colApiCallsMade.Name = "colApiCallsMade";
            this.colApiCallsMade.ReadOnly = true;
            this.colApiCallsMade.Width = 70;
            // 
            // colETThreat
            // 
            this.colETThreat.HeaderText = "ET Threat";
            this.colETThreat.Name = "colETThreat";
            this.colETThreat.ReadOnly = true;
            this.colETThreat.Width = 120;
            // 
            // colMalicious
            // 
            this.colMalicious.HeaderText = "Malicious";
            this.colMalicious.Name = "colMalicious";
            this.colMalicious.ReadOnly = true;
            this.colMalicious.Width = 80;
            // 
            // colSuspicious
            // 
            this.colSuspicious.HeaderText = "Suspicious";
            this.colSuspicious.Name = "colSuspicious";
            this.colSuspicious.ReadOnly = true;
            this.colSuspicious.Width = 80;
            // 
            // colHarmless
            // 
            this.colHarmless.HeaderText = "Harmless";
            this.colHarmless.Name = "colHarmless";
            this.colHarmless.ReadOnly = true;
            this.colHarmless.Width = 80;
            // 
            // colUndetected
            // 
            this.colUndetected.HeaderText = "Undetected";
            this.colUndetected.Name = "colUndetected";
            this.colUndetected.ReadOnly = true;
            this.colUndetected.Width = 80;
            // 
            // colStatus
            // 
            this.colStatus.HeaderText = "Status";
            this.colStatus.Name = "colStatus";
            this.colStatus.ReadOnly = true;
            this.colStatus.Width = 90;
            // 
            // colError
            // 
            this.colError.HeaderText = "Error";
            this.colError.Name = "colError";
            this.colError.ReadOnly = true;
            this.colError.Width = 120;
            // 
            // pnlControls
            // 
            this.pnlControls.Controls.Add(this.btnCopy);
            this.pnlControls.Controls.Add(this.btnUpdateET);
            this.pnlControls.Controls.Add(this.btnClear);
            this.pnlControls.Controls.Add(this.btnRefresh);
            this.pnlControls.Controls.Add(this.btnSave);
            this.pnlControls.Controls.Add(this.txtApiKey);
            this.pnlControls.Controls.Add(this.lblApiKey);
            this.pnlControls.Controls.Add(this.lblInstructions);
            this.pnlControls.Controls.Add(this.txtETProKey);
            this.pnlControls.Controls.Add(this.lblETProKey);
            this.pnlControls.Controls.Add(this.btnSaveETKey);
            this.pnlControls.Controls.Add(this.lblETStatus);
            this.pnlControls.Dock = System.Windows.Forms.DockStyle.Top;
            this.pnlControls.Location = new System.Drawing.Point(0, 0);
            this.pnlControls.Name = "pnlControls";
            this.pnlControls.Size = new System.Drawing.Size(600, 105);
            this.pnlControls.TabIndex = 1;
            // 
            // btnCopy
            // 
            this.btnCopy.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)));
            this.btnCopy.Location = new System.Drawing.Point(10, 75);
            this.btnCopy.Name = "btnCopy";
            this.btnCopy.Size = new System.Drawing.Size(85, 23);
            this.btnCopy.TabIndex = 10;
            this.btnCopy.Text = "Copy Domains";
            this.btnCopy.UseVisualStyleBackColor = true;
            this.btnCopy.Click += new System.EventHandler(this.btnCopy_Click);
            // 
            // btnUpdateET
            // 
            this.btnUpdateET.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left)));
            this.btnUpdateET.Location = new System.Drawing.Point(105, 75);
            this.btnUpdateET.Name = "btnUpdateET";
            this.btnUpdateET.Size = new System.Drawing.Size(75, 23);
            this.btnUpdateET.TabIndex = 11;
            this.btnUpdateET.Text = "Update ET";
            this.btnUpdateET.UseVisualStyleBackColor = true;
            this.btnUpdateET.Click += new System.EventHandler(this.btnUpdateET_Click);
            // 
            // btnClear
            // 
            this.btnClear.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.btnClear.Location = new System.Drawing.Point(525, 50);
            this.btnClear.Name = "btnClear";
            this.btnClear.Size = new System.Drawing.Size(65, 23);
            this.btnClear.TabIndex = 5;
            this.btnClear.Text = "Clear";
            this.btnClear.UseVisualStyleBackColor = true;
            this.btnClear.Click += new System.EventHandler(this.btnClear_Click);
            // 
            // btnRefresh
            // 
            this.btnRefresh.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.btnRefresh.Location = new System.Drawing.Point(450, 50);
            this.btnRefresh.Name = "btnRefresh";
            this.btnRefresh.Size = new System.Drawing.Size(65, 23);
            this.btnRefresh.TabIndex = 4;
            this.btnRefresh.Text = "Refresh";
            this.btnRefresh.UseVisualStyleBackColor = true;
            this.btnRefresh.Click += new System.EventHandler(this.btnRefresh_Click);
            // 
            // btnSave
            // 
            this.btnSave.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.btnSave.Location = new System.Drawing.Point(525, 25);
            this.btnSave.Name = "btnSave";
            this.btnSave.Size = new System.Drawing.Size(65, 23);
            this.btnSave.TabIndex = 3;
            this.btnSave.Text = "Save";
            this.btnSave.UseVisualStyleBackColor = true;
            this.btnSave.Click += new System.EventHandler(this.btnSave_Click);
            this.btnSave.Visible = false;
            // 
            // txtApiKey
            // 
            this.txtApiKey.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtApiKey.Location = new System.Drawing.Point(75, 27);
            this.txtApiKey.Name = "txtApiKey";
            this.txtApiKey.Size = new System.Drawing.Size(440, 20);
            this.txtApiKey.TabIndex = 2;
            this.txtApiKey.TextChanged += new System.EventHandler(this.txtApiKey_TextChanged);
            this.txtApiKey.Enter += new System.EventHandler(this.txtApiKey_Enter);
            this.txtApiKey.Leave += new System.EventHandler(this.txtApiKey_Leave);
            this.txtApiKey.Visible = false;
            // 
            // lblApiKey
            // 
            this.lblApiKey.AutoSize = true;
            this.lblApiKey.Location = new System.Drawing.Point(10, 30);
            this.lblApiKey.Name = "lblApiKey";
            this.lblApiKey.Size = new System.Drawing.Size(59, 13);
            this.lblApiKey.TabIndex = 1;
            this.lblApiKey.Text = "VT API Key:";
            this.lblApiKey.Visible = false;
            // 
            // lblStatus
            // 
            this.lblStatus.Dock = System.Windows.Forms.DockStyle.Bottom;
            this.lblStatus.Location = new System.Drawing.Point(0, 400);
            this.lblStatus.Name = "lblStatus";
            this.lblStatus.Size = new System.Drawing.Size(600, 20);
            this.lblStatus.TabIndex = 2;
            this.lblStatus.Text = "Ready";
            this.lblStatus.TextAlign = System.Drawing.ContentAlignment.MiddleLeft;
            // 
            // pnlMain
            // 
            this.pnlMain.Controls.Add(this.dgvDomains);
            this.pnlMain.Controls.Add(this.pnlControls);
            this.pnlMain.Dock = System.Windows.Forms.DockStyle.Fill;
            this.pnlMain.Location = new System.Drawing.Point(0, 0);
            this.pnlMain.Name = "pnlMain";
            this.pnlMain.Size = new System.Drawing.Size(600, 400);
            this.pnlMain.TabIndex = 3;
            // 
            // lblInstructions
            // 
            this.lblInstructions.AutoSize = true;
            this.lblInstructions.Location = new System.Drawing.Point(10, 5);
            this.lblInstructions.Name = "lblInstructions";
            this.lblInstructions.Size = new System.Drawing.Size(580, 13);
            this.lblInstructions.TabIndex = 0;
            this.lblInstructions.Text = "Domains will be analyzed automatically. Optional: enter ET Pro key below.";
            // 
            // txtETProKey
            // 
            this.txtETProKey.Anchor = ((System.Windows.Forms.AnchorStyles)(((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Left) 
            | System.Windows.Forms.AnchorStyles.Right)));
            this.txtETProKey.Location = new System.Drawing.Point(75, 27);
            this.txtETProKey.Name = "txtETProKey";
            this.txtETProKey.PasswordChar = '*';
            this.txtETProKey.Size = new System.Drawing.Size(440, 20);
            this.txtETProKey.TabIndex = 6;
            this.txtETProKey.TextChanged += new System.EventHandler(this.txtETProKey_TextChanged);
            this.txtETProKey.Enter += new System.EventHandler(this.txtETProKey_Enter);
            this.txtETProKey.Leave += new System.EventHandler(this.txtETProKey_Leave);
            // 
            // lblETProKey
            // 
            this.lblETProKey.AutoSize = true;
            this.lblETProKey.Location = new System.Drawing.Point(10, 30);
            this.lblETProKey.Name = "lblETProKey";
            this.lblETProKey.Size = new System.Drawing.Size(59, 13);
            this.lblETProKey.TabIndex = 7;
            this.lblETProKey.Text = "ET Pro Key:";
            // 
            // btnSaveETKey
            // 
            this.btnSaveETKey.Anchor = ((System.Windows.Forms.AnchorStyles)((System.Windows.Forms.AnchorStyles.Top | System.Windows.Forms.AnchorStyles.Right)));
            this.btnSaveETKey.Location = new System.Drawing.Point(525, 25);
            this.btnSaveETKey.Name = "btnSaveETKey";
            this.btnSaveETKey.Size = new System.Drawing.Size(65, 23);
            this.btnSaveETKey.TabIndex = 8;
            this.btnSaveETKey.Text = "Save ET";
            this.btnSaveETKey.UseVisualStyleBackColor = true;
            this.btnSaveETKey.Click += new System.EventHandler(this.btnSaveETKey_Click);
            // 
            // lblETStatus
            // 
            this.lblETStatus.AutoSize = true;
            this.lblETStatus.Location = new System.Drawing.Point(10, 55);
            this.lblETStatus.Name = "lblETStatus";
            this.lblETStatus.Size = new System.Drawing.Size(350, 13);
            this.lblETStatus.TabIndex = 9;
            this.lblETStatus.Text = "ET Rules: Not configured (will use free ET Open rules)";
            this.lblETStatus.ForeColor = System.Drawing.Color.DarkBlue;
            // 
            // DomainReputationUI
            // 
            this.AutoScaleDimensions = new System.Drawing.SizeF(6F, 13F);
            this.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font;
            this.Controls.Add(this.pnlMain);
            this.Controls.Add(this.lblStatus);
            this.Name = "DomainReputationUI";
            this.Size = new System.Drawing.Size(600, 420);
            this.Load += new System.EventHandler(this.DomainReputationUI_Load);
            ((System.ComponentModel.ISupportInitialize)(this.dgvDomains)).EndInit();
            this.pnlControls.ResumeLayout(false);
            this.pnlControls.PerformLayout();
            this.pnlMain.ResumeLayout(false);
            this.ResumeLayout(false);

        }

        #endregion

        private System.Windows.Forms.DataGridView dgvDomains;
        private System.Windows.Forms.Panel pnlControls;
        private System.Windows.Forms.Button btnCopy;
        private System.Windows.Forms.Button btnUpdateET;
        private System.Windows.Forms.Button btnClear;
        private System.Windows.Forms.Button btnRefresh;
        private System.Windows.Forms.Button btnSave;
        private System.Windows.Forms.TextBox txtApiKey;
        private System.Windows.Forms.Label lblApiKey;
        private System.Windows.Forms.Label lblStatus;
        private System.Windows.Forms.Panel pnlMain;
        private System.Windows.Forms.DataGridViewTextBoxColumn colDomain;
        private System.Windows.Forms.DataGridViewTextBoxColumn colRequests;
        private System.Windows.Forms.DataGridViewTextBoxColumn colApiCallsMade;
        private System.Windows.Forms.DataGridViewTextBoxColumn colETThreat;
        private System.Windows.Forms.DataGridViewTextBoxColumn colMalicious;
        private System.Windows.Forms.DataGridViewTextBoxColumn colSuspicious;
        private System.Windows.Forms.DataGridViewTextBoxColumn colHarmless;
        private System.Windows.Forms.DataGridViewTextBoxColumn colUndetected;
        private System.Windows.Forms.DataGridViewTextBoxColumn colStatus;
        private System.Windows.Forms.DataGridViewTextBoxColumn colError;
        private System.Windows.Forms.Label lblInstructions;
        private System.Windows.Forms.TextBox txtETProKey;
        private System.Windows.Forms.Label lblETProKey;
        private System.Windows.Forms.Button btnSaveETKey;
        private System.Windows.Forms.Label lblETStatus;
        private System.Windows.Forms.ContextMenuStrip contextMenuGrid;
        private System.Windows.Forms.ToolStripMenuItem menuCopySelectedDomains;
        private System.Windows.Forms.ToolStripMenuItem menuCopySelectedETThreats;
        private System.Windows.Forms.ToolStripSeparator menuSeparator1;
        private System.Windows.Forms.ToolStripMenuItem menuCopySelectedCells;
        private System.Windows.Forms.ToolStripMenuItem menuCopySelectedRows;
    }
} 