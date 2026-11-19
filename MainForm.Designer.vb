<Global.Microsoft.VisualBasic.CompilerServices.DesignerGenerated()>
Partial Class MainForm
    Inherits System.Windows.Forms.Form

    'Form remplace la méthode Dispose pour nettoyer la liste des composants.
    <System.Diagnostics.DebuggerNonUserCode()>
    Protected Overrides Sub Dispose(ByVal disposing As Boolean)
        Try
            If disposing AndAlso components IsNot Nothing Then
                components.Dispose()
            End If
        Finally
            MyBase.Dispose(disposing)
        End Try
    End Sub

    'Requise par le Concepteur Windows Form
    Private components As System.ComponentModel.IContainer

    'REMARQUE : la procédure suivante est requise par le Concepteur Windows Form
    'Elle peut être modifiée à l'aide du Concepteur Windows Form.
    <System.Diagnostics.DebuggerStepThrough()>
    Private Sub InitializeComponent()
        Me.components = New System.ComponentModel.Container()
        Me.pnlTop = New System.Windows.Forms.FlowLayoutPanel()
        Me.lblIface = New System.Windows.Forms.Label()
        Me.cboIface = New System.Windows.Forms.ComboBox()
        Me.btnRefreshIf = New System.Windows.Forms.Button()
        Me.lblDe = New System.Windows.Forms.Label()
        Me.txtStart = New System.Windows.Forms.TextBox()
        Me.lblA = New System.Windows.Forms.Label()
        Me.txtEnd = New System.Windows.Forms.TextBox()
        Me.lblPasses = New System.Windows.Forms.Label()
        Me.nudPasses = New System.Windows.Forms.NumericUpDown()
        Me.lblTimeout = New System.Windows.Forms.Label()
        Me.nudTimeout = New System.Windows.Forms.NumericUpDown()
        Me.chkDns = New System.Windows.Forms.CheckBox()
        Me.btnScan = New System.Windows.Forms.Button()
        Me.pnlTop2 = New System.Windows.Forms.FlowLayoutPanel()
        Me.chkMonitor = New System.Windows.Forms.CheckBox()
        Me.lblInterval = New System.Windows.Forms.Label()
        Me.nudInterval = New System.Windows.Forms.NumericUpDown()
        Me.chkPassive = New System.Windows.Forms.CheckBox()
        Me.btnNpcap = New System.Windows.Forms.Button()
        Me.chkConflictsOnly = New System.Windows.Forms.CheckBox()
        Me.btnExport = New System.Windows.Forms.Button()
        Me.btnClear = New System.Windows.Forms.Button()
        Me.lblSummary = New System.Windows.Forms.Label()
        Me.splitMain = New System.Windows.Forms.SplitContainer()
        Me.lv = New System.Windows.Forms.ListView()
        Me.colIp = New System.Windows.Forms.ColumnHeader()
        Me.colMac = New System.Windows.Forms.ColumnHeader()
        Me.colVendor = New System.Windows.Forms.ColumnHeader()
        Me.colHost = New System.Windows.Forms.ColumnHeader()
        Me.colPing = New System.Windows.Forms.ColumnHeader()
        Me.colStatus = New System.Windows.Forms.ColumnHeader()
        Me.colNotes = New System.Windows.Forms.ColumnHeader()
        Me.colSeen = New System.Windows.Forms.ColumnHeader()
        Me.ctxList = New System.Windows.Forms.ContextMenuStrip(Me.components)
        Me.mnuRetest = New System.Windows.Forms.ToolStripMenuItem()
        Me.mnuCopyIp = New System.Windows.Forms.ToolStripMenuItem()
        Me.mnuCopyMac = New System.Windows.Forms.ToolStripMenuItem()
        Me.mnuCopyLine = New System.Windows.Forms.ToolStripMenuItem()
        Me.grpLog = New System.Windows.Forms.GroupBox()
        Me.txtLog = New System.Windows.Forms.TextBox()
        Me.status = New System.Windows.Forms.StatusStrip()
        Me.lblStatus = New System.Windows.Forms.ToolStripStatusLabel()
        Me.pbar = New System.Windows.Forms.ToolStripProgressBar()
        Me.monitorTimer = New System.Windows.Forms.Timer(Me.components)
        Me.passiveTimer = New System.Windows.Forms.Timer(Me.components)
        Me.pnlTop.SuspendLayout()
        CType(Me.nudPasses, System.ComponentModel.ISupportInitialize).BeginInit()
        CType(Me.nudTimeout, System.ComponentModel.ISupportInitialize).BeginInit()
        Me.pnlTop2.SuspendLayout()
        CType(Me.nudInterval, System.ComponentModel.ISupportInitialize).BeginInit()
        CType(Me.splitMain, System.ComponentModel.ISupportInitialize).BeginInit()
        Me.splitMain.Panel1.SuspendLayout()
        Me.splitMain.Panel2.SuspendLayout()
        Me.splitMain.SuspendLayout()
        Me.ctxList.SuspendLayout()
        Me.grpLog.SuspendLayout()
        Me.status.SuspendLayout()
        Me.SuspendLayout()
        '
        'pnlTop
        '
        Me.pnlTop.AutoSize = True
        Me.pnlTop.Controls.Add(Me.lblIface)
        Me.pnlTop.Controls.Add(Me.cboIface)
        Me.pnlTop.Controls.Add(Me.btnRefreshIf)
        Me.pnlTop.Controls.Add(Me.lblDe)
        Me.pnlTop.Controls.Add(Me.txtStart)
        Me.pnlTop.Controls.Add(Me.lblA)
        Me.pnlTop.Controls.Add(Me.txtEnd)
        Me.pnlTop.Controls.Add(Me.lblPasses)
        Me.pnlTop.Controls.Add(Me.nudPasses)
        Me.pnlTop.Controls.Add(Me.lblTimeout)
        Me.pnlTop.Controls.Add(Me.nudTimeout)
        Me.pnlTop.Controls.Add(Me.chkDns)
        Me.pnlTop.Controls.Add(Me.btnScan)
        Me.pnlTop.Dock = System.Windows.Forms.DockStyle.Top
        Me.pnlTop.Location = New System.Drawing.Point(0, 0)
        Me.pnlTop.Name = "pnlTop"
        Me.pnlTop.Padding = New System.Windows.Forms.Padding(6)
        Me.pnlTop.Size = New System.Drawing.Size(1234, 46)
        Me.pnlTop.TabIndex = 0
        '
        'lblIface
        '
        Me.lblIface.AutoSize = True
        Me.lblIface.Name = "lblIface"
        Me.lblIface.Padding = New System.Windows.Forms.Padding(0, 6, 0, 0)
        Me.lblIface.TabIndex = 0
        Me.lblIface.Text = "Interface :"
        '
        'cboIface
        '
        Me.cboIface.DropDownStyle = System.Windows.Forms.ComboBoxStyle.DropDownList
        Me.cboIface.Name = "cboIface"
        Me.cboIface.Size = New System.Drawing.Size(430, 23)
        Me.cboIface.TabIndex = 1
        '
        'btnRefreshIf
        '
        Me.btnRefreshIf.Name = "btnRefreshIf"
        Me.btnRefreshIf.Size = New System.Drawing.Size(30, 23)
        Me.btnRefreshIf.TabIndex = 2
        Me.btnRefreshIf.Text = "↻"
        '
        'lblDe
        '
        Me.lblDe.AutoSize = True
        Me.lblDe.Name = "lblDe"
        Me.lblDe.Padding = New System.Windows.Forms.Padding(0, 6, 0, 0)
        Me.lblDe.TabIndex = 3
        Me.lblDe.Text = "De :"
        '
        'txtStart
        '
        Me.txtStart.Name = "txtStart"
        Me.txtStart.Size = New System.Drawing.Size(110, 23)
        Me.txtStart.TabIndex = 4
        '
        'lblA
        '
        Me.lblA.AutoSize = True
        Me.lblA.Name = "lblA"
        Me.lblA.Padding = New System.Windows.Forms.Padding(0, 6, 0, 0)
        Me.lblA.TabIndex = 5
        Me.lblA.Text = "à :"
        '
        'txtEnd
        '
        Me.txtEnd.Name = "txtEnd"
        Me.txtEnd.Size = New System.Drawing.Size(110, 23)
        Me.txtEnd.TabIndex = 6
        '
        'lblPasses
        '
        Me.lblPasses.AutoSize = True
        Me.lblPasses.Name = "lblPasses"
        Me.lblPasses.Padding = New System.Windows.Forms.Padding(0, 6, 0, 0)
        Me.lblPasses.TabIndex = 7
        Me.lblPasses.Text = "Passes ARP :"
        '
        'nudPasses
        '
        Me.nudPasses.Maximum = New Decimal(New Integer() {30, 0, 0, 0})
        Me.nudPasses.Minimum = New Decimal(New Integer() {1, 0, 0, 0})
        Me.nudPasses.Name = "nudPasses"
        Me.nudPasses.Size = New System.Drawing.Size(50, 23)
        Me.nudPasses.TabIndex = 8
        Me.nudPasses.Value = New Decimal(New Integer() {3, 0, 0, 0})
        '
        'lblTimeout
        '
        Me.lblTimeout.AutoSize = True
        Me.lblTimeout.Name = "lblTimeout"
        Me.lblTimeout.Padding = New System.Windows.Forms.Padding(0, 6, 0, 0)
        Me.lblTimeout.TabIndex = 9
        Me.lblTimeout.Text = "Timeout ping (ms) :"
        '
        'nudTimeout
        '
        Me.nudTimeout.Increment = New Decimal(New Integer() {100, 0, 0, 0})
        Me.nudTimeout.Maximum = New Decimal(New Integer() {5000, 0, 0, 0})
        Me.nudTimeout.Minimum = New Decimal(New Integer() {100, 0, 0, 0})
        Me.nudTimeout.Name = "nudTimeout"
        Me.nudTimeout.Size = New System.Drawing.Size(65, 23)
        Me.nudTimeout.TabIndex = 10
        Me.nudTimeout.Value = New Decimal(New Integer() {600, 0, 0, 0})
        '
        'chkDns
        '
        Me.chkDns.AutoSize = True
        Me.chkDns.Checked = True
        Me.chkDns.CheckState = System.Windows.Forms.CheckState.Checked
        Me.chkDns.Name = "chkDns"
        Me.chkDns.TabIndex = 11
        Me.chkDns.Text = "Noms DNS"
        '
        'btnScan
        '
        Me.btnScan.Name = "btnScan"
        Me.btnScan.Size = New System.Drawing.Size(90, 28)
        Me.btnScan.TabIndex = 12
        Me.btnScan.Text = "Scanner"
        '
        'pnlTop2
        '
        Me.pnlTop2.AutoSize = True
        Me.pnlTop2.Controls.Add(Me.chkMonitor)
        Me.pnlTop2.Controls.Add(Me.lblInterval)
        Me.pnlTop2.Controls.Add(Me.nudInterval)
        Me.pnlTop2.Controls.Add(Me.chkPassive)
        Me.pnlTop2.Controls.Add(Me.btnNpcap)
        Me.pnlTop2.Controls.Add(Me.chkConflictsOnly)
        Me.pnlTop2.Controls.Add(Me.btnExport)
        Me.pnlTop2.Controls.Add(Me.btnClear)
        Me.pnlTop2.Controls.Add(Me.lblSummary)
        Me.pnlTop2.Dock = System.Windows.Forms.DockStyle.Top
        Me.pnlTop2.Location = New System.Drawing.Point(0, 46)
        Me.pnlTop2.Name = "pnlTop2"
        Me.pnlTop2.Padding = New System.Windows.Forms.Padding(6, 0, 6, 4)
        Me.pnlTop2.Size = New System.Drawing.Size(1234, 38)
        Me.pnlTop2.TabIndex = 1
        '
        'chkMonitor
        '
        Me.chkMonitor.AutoSize = True
        Me.chkMonitor.Name = "chkMonitor"
        Me.chkMonitor.TabIndex = 0
        Me.chkMonitor.Text = "Surveillance continue"
        '
        'lblInterval
        '
        Me.lblInterval.AutoSize = True
        Me.lblInterval.Name = "lblInterval"
        Me.lblInterval.Padding = New System.Windows.Forms.Padding(0, 6, 0, 0)
        Me.lblInterval.TabIndex = 1
        Me.lblInterval.Text = "toutes les (s) :"
        '
        'nudInterval
        '
        Me.nudInterval.Maximum = New Decimal(New Integer() {600, 0, 0, 0})
        Me.nudInterval.Minimum = New Decimal(New Integer() {2, 0, 0, 0})
        Me.nudInterval.Name = "nudInterval"
        Me.nudInterval.Size = New System.Drawing.Size(55, 23)
        Me.nudInterval.TabIndex = 2
        Me.nudInterval.Value = New Decimal(New Integer() {10, 0, 0, 0})
        '
        'chkPassive
        '
        Me.chkPassive.AutoSize = True
        Me.chkPassive.Name = "chkPassive"
        Me.chkPassive.TabIndex = 3
        Me.chkPassive.Text = "Écoute passive ARP (Npcap)"
        '
        'btnNpcap
        '
        Me.btnNpcap.Name = "btnNpcap"
        Me.btnNpcap.Size = New System.Drawing.Size(110, 28)
        Me.btnNpcap.TabIndex = 4
        Me.btnNpcap.Text = "Installer Npcap"
        Me.btnNpcap.Visible = False
        '
        'chkConflictsOnly
        '
        Me.chkConflictsOnly.AutoSize = True
        Me.chkConflictsOnly.Name = "chkConflictsOnly"
        Me.chkConflictsOnly.TabIndex = 5
        Me.chkConflictsOnly.Text = "Conflits / anomalies seulement"
        '
        'btnExport
        '
        Me.btnExport.Name = "btnExport"
        Me.btnExport.Size = New System.Drawing.Size(90, 28)
        Me.btnExport.TabIndex = 6
        Me.btnExport.Text = "Export CSV"
        '
        'btnClear
        '
        Me.btnClear.Name = "btnClear"
        Me.btnClear.Size = New System.Drawing.Size(70, 28)
        Me.btnClear.TabIndex = 7
        Me.btnClear.Text = "Effacer"
        '
        'lblSummary
        '
        Me.lblSummary.AutoSize = True
        Me.lblSummary.Font = New System.Drawing.Font("Segoe UI", 10.0!, System.Drawing.FontStyle.Bold)
        Me.lblSummary.Name = "lblSummary"
        Me.lblSummary.Padding = New System.Windows.Forms.Padding(4)
        Me.lblSummary.TabIndex = 8
        '
        'splitMain
        '
        Me.splitMain.Dock = System.Windows.Forms.DockStyle.Fill
        Me.splitMain.Location = New System.Drawing.Point(0, 84)
        Me.splitMain.Name = "splitMain"
        Me.splitMain.Orientation = System.Windows.Forms.Orientation.Horizontal
        '
        'splitMain.Panel1
        '
        Me.splitMain.Panel1.Controls.Add(Me.lv)
        '
        'splitMain.Panel2
        '
        Me.splitMain.Panel2.Controls.Add(Me.grpLog)
        Me.splitMain.Size = New System.Drawing.Size(1234, 635)
        Me.splitMain.SplitterDistance = 457
        Me.splitMain.TabIndex = 2
        '
        'lv
        '
        Me.lv.Columns.AddRange(New System.Windows.Forms.ColumnHeader() {Me.colIp, Me.colMac, Me.colVendor, Me.colHost, Me.colPing, Me.colStatus, Me.colNotes, Me.colSeen})
        Me.lv.ContextMenuStrip = Me.ctxList
        Me.lv.Dock = System.Windows.Forms.DockStyle.Fill
        Me.lv.FullRowSelect = True
        Me.lv.GridLines = True
        Me.lv.HideSelection = False
        Me.lv.Location = New System.Drawing.Point(0, 0)
        Me.lv.Name = "lv"
        Me.lv.Size = New System.Drawing.Size(1234, 457)
        Me.lv.TabIndex = 0
        Me.lv.UseCompatibleStateImageBehavior = False
        Me.lv.View = System.Windows.Forms.View.Details
        '
        'colIp
        '
        Me.colIp.Text = "Adresse IP"
        Me.colIp.Width = 115
        '
        'colMac
        '
        Me.colMac.Text = "Adresse(s) MAC"
        Me.colMac.Width = 260
        '
        'colVendor
        '
        Me.colVendor.Text = "Fabricant"
        Me.colVendor.Width = 160
        '
        'colHost
        '
        Me.colHost.Text = "Nom d'hôte"
        Me.colHost.Width = 170
        '
        'colPing
        '
        Me.colPing.Text = "Ping"
        Me.colPing.TextAlign = System.Windows.Forms.HorizontalAlignment.Right
        Me.colPing.Width = 55
        '
        'colStatus
        '
        Me.colStatus.Text = "Statut"
        Me.colStatus.Width = 200
        '
        'colNotes
        '
        Me.colNotes.Text = "Notes"
        Me.colNotes.Width = 220
        '
        'colSeen
        '
        Me.colSeen.Text = "Vu"
        Me.colSeen.Width = 65
        '
        'ctxList
        '
        Me.ctxList.Items.AddRange(New System.Windows.Forms.ToolStripItem() {Me.mnuRetest, Me.mnuCopyIp, Me.mnuCopyMac, Me.mnuCopyLine})
        Me.ctxList.Name = "ctxList"
        '
        'mnuRetest
        '
        Me.mnuRetest.Name = "mnuRetest"
        Me.mnuRetest.Text = "Re-tester cette IP (20 passes ARP)"
        '
        'mnuCopyIp
        '
        Me.mnuCopyIp.Name = "mnuCopyIp"
        Me.mnuCopyIp.Text = "Copier IP"
        '
        'mnuCopyMac
        '
        Me.mnuCopyMac.Name = "mnuCopyMac"
        Me.mnuCopyMac.Text = "Copier MAC"
        '
        'mnuCopyLine
        '
        Me.mnuCopyLine.Name = "mnuCopyLine"
        Me.mnuCopyLine.Text = "Copier la ligne"
        '
        'grpLog
        '
        Me.grpLog.Controls.Add(Me.txtLog)
        Me.grpLog.Dock = System.Windows.Forms.DockStyle.Fill
        Me.grpLog.Location = New System.Drawing.Point(0, 0)
        Me.grpLog.Name = "grpLog"
        Me.grpLog.Size = New System.Drawing.Size(1234, 174)
        Me.grpLog.TabIndex = 0
        Me.grpLog.TabStop = False
        Me.grpLog.Text = "Journal / alertes"
        '
        'txtLog
        '
        Me.txtLog.BackColor = System.Drawing.Color.White
        Me.txtLog.Dock = System.Windows.Forms.DockStyle.Fill
        Me.txtLog.Font = New System.Drawing.Font("Consolas", 9.0!)
        Me.txtLog.Multiline = True
        Me.txtLog.Name = "txtLog"
        Me.txtLog.ReadOnly = True
        Me.txtLog.ScrollBars = System.Windows.Forms.ScrollBars.Vertical
        Me.txtLog.TabIndex = 0
        '
        'status
        '
        Me.status.Items.AddRange(New System.Windows.Forms.ToolStripItem() {Me.lblStatus, Me.pbar})
        Me.status.Location = New System.Drawing.Point(0, 719)
        Me.status.Name = "status"
        Me.status.Size = New System.Drawing.Size(1234, 22)
        Me.status.TabIndex = 3
        '
        'lblStatus
        '
        Me.lblStatus.Name = "lblStatus"
        Me.lblStatus.Spring = True
        Me.lblStatus.Text = "Prêt."
        Me.lblStatus.TextAlign = System.Drawing.ContentAlignment.MiddleLeft
        '
        'pbar
        '
        Me.pbar.Name = "pbar"
        Me.pbar.Size = New System.Drawing.Size(250, 16)
        '
        'passiveTimer
        '
        Me.passiveTimer.Interval = 1000
        '
        'MainForm
        '
        Me.AutoScaleDimensions = New System.Drawing.SizeF(7.0!, 15.0!)
        Me.AutoScaleMode = System.Windows.Forms.AutoScaleMode.Font
        Me.ClientSize = New System.Drawing.Size(1234, 741)
        Me.Controls.Add(Me.splitMain)
        Me.Controls.Add(Me.pnlTop2)
        Me.Controls.Add(Me.pnlTop)
        Me.Controls.Add(Me.status)
        Me.Font = New System.Drawing.Font("Segoe UI", 9.0!)
        Me.Name = "MainForm"
        Me.StartPosition = System.Windows.Forms.FormStartPosition.CenterScreen
        Me.Text = "IP Conflict Scanner — NRI"
        Me.pnlTop.ResumeLayout(False)
        Me.pnlTop.PerformLayout()
        CType(Me.nudPasses, System.ComponentModel.ISupportInitialize).EndInit()
        CType(Me.nudTimeout, System.ComponentModel.ISupportInitialize).EndInit()
        Me.pnlTop2.ResumeLayout(False)
        Me.pnlTop2.PerformLayout()
        CType(Me.nudInterval, System.ComponentModel.ISupportInitialize).EndInit()
        Me.splitMain.Panel1.ResumeLayout(False)
        Me.splitMain.Panel2.ResumeLayout(False)
        CType(Me.splitMain, System.ComponentModel.ISupportInitialize).EndInit()
        Me.splitMain.ResumeLayout(False)
        Me.ctxList.ResumeLayout(False)
        Me.grpLog.ResumeLayout(False)
        Me.grpLog.PerformLayout()
        Me.status.ResumeLayout(False)
        Me.status.PerformLayout()
        Me.ResumeLayout(False)
        Me.PerformLayout()

    End Sub

    Friend WithEvents pnlTop As System.Windows.Forms.FlowLayoutPanel
    Friend WithEvents lblIface As System.Windows.Forms.Label
    Friend WithEvents cboIface As System.Windows.Forms.ComboBox
    Friend WithEvents btnRefreshIf As System.Windows.Forms.Button
    Friend WithEvents lblDe As System.Windows.Forms.Label
    Friend WithEvents txtStart As System.Windows.Forms.TextBox
    Friend WithEvents lblA As System.Windows.Forms.Label
    Friend WithEvents txtEnd As System.Windows.Forms.TextBox
    Friend WithEvents lblPasses As System.Windows.Forms.Label
    Friend WithEvents nudPasses As System.Windows.Forms.NumericUpDown
    Friend WithEvents lblTimeout As System.Windows.Forms.Label
    Friend WithEvents nudTimeout As System.Windows.Forms.NumericUpDown
    Friend WithEvents chkDns As System.Windows.Forms.CheckBox
    Friend WithEvents btnScan As System.Windows.Forms.Button
    Friend WithEvents pnlTop2 As System.Windows.Forms.FlowLayoutPanel
    Friend WithEvents chkMonitor As System.Windows.Forms.CheckBox
    Friend WithEvents lblInterval As System.Windows.Forms.Label
    Friend WithEvents nudInterval As System.Windows.Forms.NumericUpDown
    Friend WithEvents chkPassive As System.Windows.Forms.CheckBox
    Friend WithEvents btnNpcap As System.Windows.Forms.Button
    Friend WithEvents chkConflictsOnly As System.Windows.Forms.CheckBox
    Friend WithEvents btnExport As System.Windows.Forms.Button
    Friend WithEvents btnClear As System.Windows.Forms.Button
    Friend WithEvents lblSummary As System.Windows.Forms.Label
    Friend WithEvents splitMain As System.Windows.Forms.SplitContainer
    Friend WithEvents lv As System.Windows.Forms.ListView
    Friend WithEvents colIp As System.Windows.Forms.ColumnHeader
    Friend WithEvents colMac As System.Windows.Forms.ColumnHeader
    Friend WithEvents colVendor As System.Windows.Forms.ColumnHeader
    Friend WithEvents colHost As System.Windows.Forms.ColumnHeader
    Friend WithEvents colPing As System.Windows.Forms.ColumnHeader
    Friend WithEvents colStatus As System.Windows.Forms.ColumnHeader
    Friend WithEvents colNotes As System.Windows.Forms.ColumnHeader
    Friend WithEvents colSeen As System.Windows.Forms.ColumnHeader
    Friend WithEvents ctxList As System.Windows.Forms.ContextMenuStrip
    Friend WithEvents mnuRetest As System.Windows.Forms.ToolStripMenuItem
    Friend WithEvents mnuCopyIp As System.Windows.Forms.ToolStripMenuItem
    Friend WithEvents mnuCopyMac As System.Windows.Forms.ToolStripMenuItem
    Friend WithEvents mnuCopyLine As System.Windows.Forms.ToolStripMenuItem
    Friend WithEvents grpLog As System.Windows.Forms.GroupBox
    Friend WithEvents txtLog As System.Windows.Forms.TextBox
    Friend WithEvents status As System.Windows.Forms.StatusStrip
    Friend WithEvents lblStatus As System.Windows.Forms.ToolStripStatusLabel
    Friend WithEvents pbar As System.Windows.Forms.ToolStripProgressBar
    Friend WithEvents monitorTimer As System.Windows.Forms.Timer
    Friend WithEvents passiveTimer As System.Windows.Forms.Timer
End Class
