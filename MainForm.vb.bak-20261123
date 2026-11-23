Imports System.Collections
Imports System.Drawing
Imports System.IO
Imports System.Net
Imports System.Net.NetworkInformation
Imports System.Text
Imports System.Threading
Imports System.Windows.Forms

Partial Public Class MainForm

    ' Les contrôles sont déclarés dans MainForm.Designer.vb (Concepteur de vues)

    ' --- État ---
    Private ReadOnly _hosts As New Dictionary(Of UInteger, HostResult)
    Private ReadOnly _arpHistory As New Dictionary(Of String, String)
    Private ReadOnly _oui As New OuiDatabase()
    Private _cts As CancellationTokenSource
    Private _monitorBusy As Integer = 0
    Private _sortCol As Integer = 0
    Private _sortAsc As Boolean = True
    Private _currentIface As LocalInterface
    Private _pcap As PcapArp
    Private ReadOnly _dirty As New HashSet(Of UInteger)
    Private ReadOnly _alerted As New HashSet(Of String)(StringComparer.OrdinalIgnoreCase)
    Private Const OuiUrl As String = "https://standards-oui.ieee.org/oui/oui.csv"

    Public Sub New()
        InitializeComponent()
        Text &= If(IsAdmin(), "  [Administrateur]", "  [NON admin : détection limitée]")
        WireEvents()
        AddHandler Shown, Sub() LoadOuiAsync()
        If PcapArp.IsAvailable() Then
            Log("Npcap détecté : écoute passive ARP disponible (conflits + appareils hors sous-réseau).")
        Else
            chkPassive.Enabled = False
            btnNpcap.Visible = True
            Log("Npcap absent : écoute passive indisponible. Bouton « Installer Npcap » pour l'installer depuis npcap.com.")
        End If
        If Not IsAdmin() Then Log("[!] Lancer en administrateur pour purger le cache ARP entre les passes (sinon les conflits peuvent passer inaperçus).")
        LoadInterfaces()
    End Sub

    ''' <summary>Branchement des événements (les contrôles viennent du Concepteur).</summary>
    Private Sub WireEvents()
        AddHandler lv.ColumnClick, AddressOf Lv_ColumnClick
        AddHandler mnuRetest.Click, AddressOf Ctx_Retest
        AddHandler mnuCopyIp.Click, Sub() CopySel(0)
        AddHandler mnuCopyMac.Click, Sub() CopySel(1)
        AddHandler mnuCopyLine.Click, Sub() CopySel(-1)
        AddHandler Shown, Sub() splitMain.SplitterDistance = CInt(splitMain.Height * 0.72)

        AddHandler btnRefreshIf.Click, Sub() LoadInterfaces()
        AddHandler cboIface.SelectedIndexChanged, AddressOf CboIface_Changed
        AddHandler btnScan.Click, AddressOf BtnScan_Click
        AddHandler btnExport.Click, AddressOf BtnExport_Click
        AddHandler btnClear.Click, Sub()
                                       _hosts.Clear() : _arpHistory.Clear() : lv.Items.Clear() : UpdateSummary()
                                   End Sub
        AddHandler chkConflictsOnly.CheckedChanged, Sub() RefreshList()
        AddHandler chkMonitor.CheckedChanged, AddressOf ChkMonitor_Changed
        AddHandler nudInterval.ValueChanged, Sub() monitorTimer.Interval = CInt(nudInterval.Value) * 1000
        AddHandler monitorTimer.Tick, AddressOf MonitorTimer_Tick
        AddHandler chkPassive.CheckedChanged, AddressOf ChkPassive_Changed
        AddHandler btnNpcap.Click, AddressOf BtnNpcap_Click
        AddHandler passiveTimer.Tick, AddressOf PassiveTimer_Tick
    End Sub

    ' ================== Interfaces ==================

    Private Sub LoadInterfaces()
        cboIface.Items.Clear()
        For Each i In LocalInterface.Enumerate()
            cboIface.Items.Add(i)
            If i.DadState = DuplicateAddressDetectionState.Duplicate Then
                Log($"[CONFLIT] Windows signale l'adresse {i.Address} ({i.Name}) comme DUPLIQUÉE sur le réseau !")
            End If
        Next
        If cboIface.Items.Count > 0 Then
            ' privilégie une interface avec passerelle, puis la plus petite plage (évite VPN/Docker larges)
            Dim idx = 0
            Dim best = -1
            For k = 0 To cboIface.Items.Count - 1
                Dim li = DirectCast(cboIface.Items(k), LocalInterface)
                Dim score = If(li.Gateway IsNot Nothing, 1000, 0) + li.PrefixLength
                If score > best Then best = score : idx = k
            Next
            cboIface.SelectedIndex = idx
        Else
            Log("Aucune interface IPv4 active trouvée.")
        End If
    End Sub

    Private Sub CboIface_Changed(sender As Object, e As EventArgs)
        Dim i = TryCast(cboIface.SelectedItem, LocalInterface)
        If i Is Nothing Then Return
        If chkPassive.Checked Then chkPassive.Checked = False ' l'écoute est liée à l'interface
        _currentIface = i
        Dim first = i.FirstHost, last = i.LastHost
        ' limite par défaut à /22 (1022 hôtes) pour éviter des scans interminables
        If ToHostUInt(last) - ToHostUInt(first) > 1022UI Then
            Dim baseU = ToHostUInt(i.Address) And &HFFFFFF00UI
            first = FromHostUInt(baseU + 1UI)
            last = FromHostUInt(baseU + 254UI)
            Log($"Réseau /{i.PrefixLength} très large : plage réduite par défaut à {first} - {last} (modifiable).")
        End If
        txtStart.Text = first.ToString()
        txtEnd.Text = last.ToString()
        lblStatus.Text = $"{i.Name} : {i.Address}/{i.PrefixLength}  passerelle {If(i.Gateway?.ToString(), "aucune")}  MAC {i.Mac}  ifIndex {i.IfIndex}"
    End Sub

    ' ================== Scan ==================

    Private Async Sub BtnScan_Click(sender As Object, e As EventArgs)
        If _cts IsNot Nothing Then
            _cts.Cancel()
            Return
        End If
        Dim iface = TryCast(cboIface.SelectedItem, LocalInterface)
        If iface Is Nothing Then Return
        Dim a As IPAddress = Nothing, b As IPAddress = Nothing
        If Not IPAddress.TryParse(txtStart.Text.Trim(), a) OrElse Not IPAddress.TryParse(txtEnd.Text.Trim(), b) Then
            MessageBox.Show(Me, "Plage IP invalide.", "Erreur", MessageBoxButtons.OK, MessageBoxIcon.Warning)
            Return
        End If
        Dim count = CLng(Math.Abs(CLng(ToHostUInt(b)) - CLng(ToHostUInt(a)))) + 1
        If count > 4096 AndAlso MessageBox.Show(Me, $"{count} adresses à scanner, continuer ?", "Plage large", MessageBoxButtons.YesNo, MessageBoxIcon.Question) <> DialogResult.Yes Then Return

        Dim opt As New ScanOptions With {
            .Iface = iface, .StartIp = a, .EndIp = b,
            .Passes = CInt(nudPasses.Value), .PingTimeoutMs = CInt(nudTimeout.Value),
            .ResolveNames = chkDns.Checked, .PurgeArpCache = True
        }
        _cts = New CancellationTokenSource()
        btnScan.Text = "Arrêter"
        SetInputs(False)
        pbar.Value = 0
        Dim sw = Stopwatch.StartNew()
        Log($"Scan {a} → {b} sur {iface.Name} ({opt.Passes} passes ARP)...")

        Dim prog As New Progress(Of ScanProgress)(
            Sub(p)
                If p.Total > 0 Then
                    pbar.Maximum = p.Total
                    pbar.Value = Math.Min(p.Done, p.Total)
                    lblStatus.Text = $"Scan... {p.Done * 100 \ Math.Max(1, p.Total)} %"
                End If
                If p.Message IsNot Nothing Then Log(p.Message)
                If p.Host IsNot Nothing Then MergeHost(p.Host)
            End Sub)

        Try
            Dim res = Await Scanner.RunAsync(opt, prog, _cts.Token)
            For Each h In res
                MergeHost(h)
            Next
            ' ré-analyse globale sur l'ensemble (scans précédents + surveillance)
            Scanner.Analyze(_hosts.Values.ToList(), iface)
            RefreshList()
            For Each h In res
                _arpHistory(h.Ip.ToString()) = If(h.PrimaryMac, "")
            Next
            Dim conflicts = res.Where(Function(h) h.Severity = 2).ToList()
            Log($"Terminé en {sw.Elapsed.TotalSeconds:0.0} s : {res.Count} hôtes, {conflicts.Count} conflit(s).")
            For Each c In conflicts
                Log($"[CONFLIT] {c.Ip} → {c.MacList}  {DescribeMacs(c)}")
                If c.ResponderText <> "" Then Log($"          {c.ResponderText}")
            Next
            If conflicts.Count > 0 Then
                System.Media.SystemSounds.Exclamation.Play()
            End If
        Catch ex As OperationCanceledException
            Log("Scan annulé.")
        Catch ex As Exception
            Log("Erreur : " & ex.Message)
        Finally
            _cts.Dispose()
            _cts = Nothing
            btnScan.Text = "Scanner"
            SetInputs(True)
            pbar.Value = 0
            lblStatus.Text = "Prêt."
            UpdateSummary()
        End Try
    End Sub

    Private Sub SetInputs(enabled As Boolean)
        cboIface.Enabled = enabled
        btnRefreshIf.Enabled = enabled
        txtStart.Enabled = enabled
        txtEnd.Enabled = enabled
        nudPasses.Enabled = enabled
        nudTimeout.Enabled = enabled
        chkDns.Enabled = enabled
    End Sub

    Private Function DescribeMacs(h As HostResult) As String
        Return String.Join(" / ", h.Macs.Keys.Select(Function(m)
                                                         Dim v = _oui.Lookup(m)
                                                         Return If(v = "", m, $"{m} = {v}")
                                                     End Function))
    End Function

    ''' <summary>Fusionne un résultat dans l'état global et met à jour la ligne.</summary>
    Private Sub MergeHost(h As HostResult)
        Dim key = h.IpSort
        Dim cur As HostResult = Nothing
        If _hosts.TryGetValue(key, cur) Then
            If Not ReferenceEquals(cur, h) Then
                ' le nouvel objet remplace l'ancien, en héritant de son historique (une seule fois)
                For Each kv In cur.Macs
                    For n = 1 To kv.Value
                        h.AddMac(kv.Key)
                    Next
                Next
                h.Flags = h.Flags Or (cur.Flags And (HostFlags.MacChanged Or HostFlags.SelfConflict Or HostFlags.IpConflict))
                If h.PingMs < 0 Then h.PingMs = cur.PingMs
                If h.Hostname = "" Then h.Hostname = cur.Hostname
                If cur.Notes <> "" AndAlso Not h.Notes.Contains(cur.Notes) Then h.Notes = If(h.Notes = "", cur.Notes, h.Notes & " ; " & cur.Notes)
                If cur.LastSeen > h.LastSeen Then h.LastSeen = cur.LastSeen
                For Each kv In cur.ResponderPairs
                    h.ResponderPairs.AddOrUpdate(kv.Key, kv.Value, Function(k, v) v + kv.Value)
                Next
                _hosts(key) = h
                cur = h
            End If
        Else
            _hosts(key) = h
            cur = h
        End If
        UpdateRow(cur)
    End Sub

    ' ================== Affichage ==================

    Private Sub UpdateRow(h As HostResult)
        Dim key = h.Ip.ToString()
        Dim visible = Not chkConflictsOnly.Checked OrElse h.Severity > 0
        Dim it As ListViewItem = If(lv.Items.ContainsKey(key), lv.Items(key), Nothing)
        If Not visible Then
            If it IsNot Nothing Then lv.Items.Remove(it)
            Return
        End If
        If it Is Nothing Then
            it = New ListViewItem(key) With {.Name = key}
            For i = 1 To 7
                it.SubItems.Add("")
            Next
            lv.Items.Add(it)
        End If
        it.Tag = h
        it.SubItems(1).Text = h.MacList
        it.SubItems(2).Text = String.Join(" | ", h.Macs.Keys.Select(Function(m) _oui.Lookup(m)).Where(Function(v) v <> "").Distinct())
        it.SubItems(3).Text = h.Hostname
        it.SubItems(4).Text = If(h.PingMs >= 0, h.PingMs.ToString(), "-")
        it.SubItems(5).Text = h.StatusText
        it.SubItems(6).Text = NotesOf(h)
        it.SubItems(7).Text = If(h.LastSeen = Date.MinValue, "", h.LastSeen.ToString("HH:mm:ss"))
        Select Case h.Severity
            Case 2
                it.BackColor = Color.FromArgb(255, 205, 205)
                it.ForeColor = Color.DarkRed
                it.Font = New Font(lv.Font, FontStyle.Bold)
            Case 1
                it.BackColor = Color.FromArgb(255, 235, 190)
                it.ForeColor = Color.SaddleBrown
                it.Font = lv.Font
            Case Else
                it.BackColor = If(h.Flags.HasFlag(HostFlags.LocalHost), Color.FromArgb(220, 235, 255),
                               If(h.Flags.HasFlag(HostFlags.Gateway), Color.FromArgb(225, 245, 225), Color.White))
                it.ForeColor = Color.Black
                it.Font = lv.Font
        End Select
        UpdateSummary()
    End Sub

    Private Shared Function NotesOf(h As HostResult) As String
        Return h.Notes   ' notes courtes ; le détail 1ère/dernière réponse reste dans le journal
    End Function

    Private Sub RefreshList()
        lv.BeginUpdate()
        lv.Items.Clear()
        For Each h In _hosts.Values.OrderBy(Function(x) x.IpSort)
            UpdateRow(h)
        Next
        ApplySort()
        lv.EndUpdate()
        UpdateSummary()
    End Sub

    Private Sub UpdateSummary()
        Dim total = _hosts.Count
        Dim conf = _hosts.Values.Where(Function(h) h.Severity = 2).Count()
        Dim warn = _hosts.Values.Where(Function(h) h.Severity = 1).Count()
        Dim wrong = _hosts.Values.Where(Function(h) h.Flags.HasFlag(HostFlags.WrongSubnet)).Count()
        lblSummary.Text = $"{total} hôtes   |   {conf} conflit(s)   |   {warn - wrong} MAC multi-IP   |   {wrong} hors sous-réseau"
        lblSummary.ForeColor = If(conf > 0, Color.DarkRed, If(warn > 0, Color.SaddleBrown, Color.DarkGreen))
    End Sub

    Private Sub Log(msg As String)
        If txtLog.IsDisposed Then Return
        txtLog.AppendText($"{DateTime.Now:HH:mm:ss}  {msg}{Environment.NewLine}")
    End Sub

    ' ================== Tri ==================

    Private Sub Lv_ColumnClick(sender As Object, e As ColumnClickEventArgs)
        If e.Column = _sortCol Then _sortAsc = Not _sortAsc Else _sortCol = e.Column : _sortAsc = True
        ApplySort()
    End Sub

    Private Sub ApplySort()
        lv.ListViewItemSorter = New ItemComparer(_sortCol, _sortAsc)
        lv.Sort()
    End Sub

    Private Class ItemComparer
        Implements IComparer
        Private ReadOnly _col As Integer
        Private ReadOnly _asc As Boolean
        Public Sub New(col As Integer, asc As Boolean)
            _col = col : _asc = asc
        End Sub
        Public Function Compare(x As Object, y As Object) As Integer Implements IComparer.Compare
            Dim a = DirectCast(x, ListViewItem), b = DirectCast(y, ListViewItem)
            Dim ha = TryCast(a.Tag, HostResult), hb = TryCast(b.Tag, HostResult)
            Dim r As Integer
            If ha IsNot Nothing AndAlso hb IsNot Nothing AndAlso (_col = 0 OrElse _col = 4 OrElse _col = 5) Then
                Select Case _col
                    Case 0 : r = ha.IpSort.CompareTo(hb.IpSort)
                    Case 4 : r = ha.PingMs.CompareTo(hb.PingMs)
                    Case Else
                        r = hb.Severity.CompareTo(ha.Severity)
                        If r = 0 Then r = ha.IpSort.CompareTo(hb.IpSort)
                End Select
            Else
                r = String.Compare(a.SubItems(_col).Text, b.SubItems(_col).Text, StringComparison.CurrentCultureIgnoreCase)
            End If
            Return If(_asc, r, -r)
        End Function
    End Class

    ' ================== Menu contextuel ==================

    Private Sub CopySel(col As Integer)
        If lv.SelectedItems.Count = 0 Then Return
        Dim sb As New StringBuilder()
        For Each it As ListViewItem In lv.SelectedItems
            If col < 0 Then
                sb.AppendLine(String.Join(vbTab, it.SubItems.Cast(Of ListViewItem.ListViewSubItem)().Select(Function(s) s.Text)))
            Else
                sb.AppendLine(it.SubItems(col).Text)
            End If
        Next
        Clipboard.SetText(sb.ToString().TrimEnd())
    End Sub

    Private Async Sub Ctx_Retest(sender As Object, e As EventArgs)
        If lv.SelectedItems.Count = 0 OrElse _currentIface Is Nothing Then Return
        Dim h = TryCast(lv.SelectedItems(0).Tag, HostResult)
        If h Is Nothing Then Return
        Dim iface = _currentIface
        Dim admin = IsAdmin()
        Log($"Re-test {h.Ip} (20 passes ARP)...")
        Dim probes = Await Task.Run(Function()
                                        Dim l As New List(Of (First As String, Last As String))
                                        Dim rnd As New Random()
                                        For i = 1 To 20
                                            Dim r = Scanner.ProbeArpPair(iface, h.Ip, admin)
                                            If r.First <> "" Then l.Add(r)
                                            Thread.Sleep(50 + rnd.Next(200))
                                        Next
                                        Return l
                                    End Function)
        If probes.Count = 0 Then
            Log($"  {h.Ip} : aucune réponse ARP.")
        Else
            Dim seen As New Dictionary(Of String, Integer)(StringComparer.OrdinalIgnoreCase)
            Dim dualCount = 0
            For Each r In probes
                If h.AddProbe(r.First, r.Last) Then dualCount += 1
                For Each m In {r.First, r.Last}
                    If m <> "" Then seen(m) = If(seen.ContainsKey(m), seen(m) + 1, 1)
                Next
            Next
            Log($"  {h.Ip} : " & String.Join(", ", seen.Select(Function(kv) $"{kv.Key} x{kv.Value} {_oui.Lookup(kv.Key)}")) &
                If(seen.Count > 1, $"  ==> CONFLIT CONFIRMÉ ({dualCount}/{probes.Count} sondes avec 2 répondeurs)", "  ==> une seule MAC, pas de conflit"))
            Scanner.Analyze(_hosts.Values.ToList(), iface)
            UpdateRow(h)
        End If
    End Sub

    ' ================== Surveillance continue ==================

    Private Sub ChkMonitor_Changed(sender As Object, e As EventArgs)
        If chkMonitor.Checked Then
            If _currentIface Is Nothing Then chkMonitor.Checked = False : Return
            For Each h In _hosts.Values
                If Not _arpHistory.ContainsKey(h.Ip.ToString()) Then _arpHistory(h.Ip.ToString()) = If(h.PrimaryMac, "")
            Next
            monitorTimer.Interval = CInt(nudInterval.Value) * 1000
            monitorTimer.Start()
            Log($"Surveillance démarrée (toutes les {nudInterval.Value} s) : table ARP + re-sondage actif des hôtes connus + état DAD.")
            MonitorTimer_Tick(Nothing, EventArgs.Empty)
        Else
            monitorTimer.Stop()
            Log("Surveillance arrêtée.")
        End If
    End Sub

    Private Async Sub MonitorTimer_Tick(sender As Object, e As EventArgs)
        If Interlocked.Exchange(_monitorBusy, 1) = 1 Then Return
        Try
            Dim iface = _currentIface
            If iface Is Nothing Then Return
            Dim admin = IsAdmin()
            Dim known = _hosts.Values.Select(Function(h) h.Ip).ToList()

            Dim res = Await Task.Run(Function()
                                         ' 1) table ARP passive
                                         Dim arp = ReadArpTable(iface.IfIndex)
                                         ' 2) re-sondage actif des hôtes connus (purge + ARP)
                                         Dim active As New List(Of Tuple(Of IPAddress, String, String))
                                         Parallel.ForEach(known, New ParallelOptions With {.MaxDegreeOfParallelism = 16},
                                                          Sub(ip)
                                                              If ip.Equals(iface.Address) Then Return
                                                              Dim r = Scanner.ProbeArpPair(iface, ip, admin)
                                                              If r.First <> "" Then
                                                                  SyncLock active
                                                                      active.Add(Tuple.Create(ip, r.First, r.Last))
                                                                  End SyncLock
                                                              End If
                                                          End Sub)
                                         ' 3) état DAD de l'adresse locale
                                         Dim dup = LocalInterface.Enumerate().Any(Function(i) i.Address.Equals(iface.Address) AndAlso i.DadState = DuplicateAddressDetectionState.Duplicate)
                                         Return Tuple.Create(arp, active, dup)
                                     End Function)

            If res.Item3 Then
                Dim self As HostResult = Nothing
                If _hosts.TryGetValue(ToHostUInt(iface.Address), self) AndAlso Not self.Flags.HasFlag(HostFlags.SelfConflict) Then
                    self.Flags = self.Flags Or HostFlags.SelfConflict
                    UpdateRow(self)
                End If
                Log($"[CONFLIT] Windows détecte un doublon de VOTRE adresse {iface.Address} !")
                System.Media.SystemSounds.Hand.Play()
            End If

            Dim alert = False
            ' sondes actives : 2 MAC différentes pour une même requête = conflit
            For Each a In res.Item2
                Dim hh As HostResult = Nothing
                If Not _hosts.TryGetValue(ToHostUInt(a.Item1), hh) Then Continue For
                Dim pairKey = $"1ère={a.Item2} / dernière={a.Item3}"
                Dim isNewPair = Not hh.ResponderPairs.ContainsKey(pairKey)
                If hh.AddProbe(a.Item2, a.Item3) AndAlso isNewPair Then
                    Log($"[CONFLIT] {a.Item1} : 2 MAC répondent — {a.Item2} ({_oui.Lookup(a.Item2)}) et {a.Item3} ({_oui.Lookup(a.Item3)})")
                    alert = True
                End If
            Next
            Dim obs As New List(Of Tuple(Of IPAddress, String))
            obs.AddRange(res.Item1.Select(Function(a) Tuple.Create(a.Ip, a.Mac)))
            obs.AddRange(res.Item2.Select(Function(a) Tuple.Create(a.Item1, a.Item2)))
            For Each o In obs
                Dim ip = o.Item1, mac = o.Item2
                Dim key = ip.ToString()
                Dim h As HostResult = Nothing
                If Not _hosts.TryGetValue(ToHostUInt(ip), h) Then
                    h = New HostResult With {.Ip = ip, .LastSeen = DateTime.Now}
                    h.AddMac(mac)
                    _hosts(ToHostUInt(ip)) = h
                    _arpHistory(key) = mac
                    Log($"[NOUVEAU] {ip} {mac} {_oui.Lookup(mac)}")
                    UpdateRow(h)
                    Continue For
                End If
                h.LastSeen = DateTime.Now
                Dim prev As String = Nothing
                _arpHistory.TryGetValue(key, prev)
                ' alerte seulement si cette MAC n'a jamais été vue pour cette IP (évite les alertes en boucle sur un conflit connu)
                If Not String.IsNullOrEmpty(prev) AndAlso Not prev.Equals(mac, StringComparison.OrdinalIgnoreCase) AndAlso Not h.Macs.ContainsKey(mac) Then
                    h.Flags = h.Flags Or HostFlags.MacChanged
                    h.AddMac(mac)
                    Dim isGw = iface.Gateway IsNot Nothing AndAlso ip.Equals(iface.Gateway)
                    Log($"[ALERTE] {ip} : MAC {prev} → {mac} ({_oui.Lookup(mac)})" &
                        If(isGw, "  *** PASSERELLE : conflit ou usurpation ARP possible ***", "  conflit IP probable"))
                    alert = True
                Else
                    h.AddMac(mac)
                End If
                _arpHistory(key) = mac
                UpdateRow(h)
            Next
            Scanner.Analyze(_hosts.Values.ToList(), iface)
            For Each h In _hosts.Values.Where(Function(x) x.Severity > 0)
                UpdateRow(h)
            Next
            If alert Then System.Media.SystemSounds.Exclamation.Play()
            lblStatus.Text = $"Surveillance : dernier passage {DateTime.Now:HH:mm:ss} ({obs.Count} observations)"
        Catch ex As Exception
            Log("Erreur surveillance : " & ex.Message)
        Finally
            Interlocked.Exchange(_monitorBusy, 0)
        End Try
    End Sub

    ' ================== Export ==================

    Private Sub BtnExport_Click(sender As Object, e As EventArgs)
        If _hosts.Count = 0 Then Return
        Using dlg As New SaveFileDialog With {.Filter = "CSV (*.csv)|*.csv", .FileName = $"scan_{DateTime.Now:yyyyMMdd_HHmmss}.csv"}
            If dlg.ShowDialog(Me) <> DialogResult.OK Then Return
            Dim sb As New StringBuilder()
            sb.AppendLine("IP;MAC;Fabricant;Nom;Ping_ms;Statut;Notes;Vu")
            For Each h In _hosts.Values.OrderBy(Function(x) x.IpSort)
                Dim vendors = String.Join(" | ", h.Macs.Keys.Select(Function(m) _oui.Lookup(m)).Where(Function(v) v <> "").Distinct())
                sb.AppendLine(String.Join(";", New String() {
                    h.Ip.ToString(), Csv(h.MacList), Csv(vendors), Csv(h.Hostname),
                    If(h.PingMs >= 0, h.PingMs.ToString(), ""), Csv(h.StatusText), Csv(NotesOf(h)),
                    If(h.LastSeen = Date.MinValue, "", h.LastSeen.ToString("yyyy-MM-dd HH:mm:ss"))
                }))
            Next
            File.WriteAllText(dlg.FileName, sb.ToString(), New UTF8Encoding(True))
            Log($"Export : {dlg.FileName}")
        End Using
    End Sub

    Private Shared Function Csv(s As String) As String
        If s Is Nothing Then Return ""
        If s.Contains(";"c) OrElse s.Contains(""""c) Then Return """" & s.Replace("""", """""") & """"
        Return s
    End Function

    ' ================== Base fabricants (OUI) ==================

    Private Async Sub LoadOuiAsync()
        Dim exeFile = Path.Combine(AppContext.BaseDirectory, "oui.csv")
        Dim dataFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "IpConflictScanner", "oui.csv")
        For Each f In {exeFile, dataFile}
            If File.Exists(f) Then
                Log($"Base OUI chargée : {_oui.LoadCsv(f)} fabricants ({f}).")
                If File.GetLastWriteTime(f) > DateTime.Now.AddDays(-180) Then
                    RefreshList()
                    Return
                End If
                Log("Base OUI de plus de 6 mois : mise à jour...")
                Exit For
            End If
        Next
        Log("Téléchargement de la base fabricants (oui.csv IEEE)...")
        Try
            Dim bytes As Byte()
            Using http As New System.Net.Http.HttpClient With {.Timeout = TimeSpan.FromSeconds(90)}
                http.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) IpConflictScanner/1.0")
                bytes = Await http.GetByteArrayAsync(OuiUrl)
            End Using
            If bytes.Length < 100000 Then Throw New InvalidDataException($"réponse trop courte ({bytes.Length} octets)")
            Dim target = exeFile
            Try
                File.WriteAllBytes(target, bytes)
            Catch
                Directory.CreateDirectory(Path.GetDirectoryName(dataFile))
                target = dataFile
                File.WriteAllBytes(target, bytes)
            End Try
            Log($"Base OUI téléchargée : {_oui.LoadCsv(target)} fabricants ({target}).")
            RefreshList()
        Catch ex As Exception
            Log($"Échec du téléchargement de oui.csv : {ex.Message}. Le placer à la main à côté de l'exe ({OuiUrl}).")
        End Try
    End Sub

    ' ================== Installation Npcap ==================

    ''' <summary>
    ''' Télécharge l'installateur officiel depuis npcap.com et le lance (l'utilisateur valide l'installation).
    ''' Npcap n'est pas redistribuable : il est récupéré à la source, jamais embarqué.
    ''' </summary>
    Private Async Sub BtnNpcap_Click(sender As Object, e As EventArgs)
        If MessageBox.Show(Me,
            "Npcap (pilote de capture réseau du projet Nmap) va être téléchargé depuis npcap.com puis son installateur sera lancé." & vbCrLf & vbCrLf &
            "Licence gratuite : usage sur 5 machines maximum." & vbCrLf & "Continuer ?",
            "Installer Npcap", MessageBoxButtons.YesNo, MessageBoxIcon.Question) <> DialogResult.Yes Then Return
        btnNpcap.Enabled = False
        Try
            Dim url = "https://npcap.com/dist/npcap-1.88.exe"
            Using http As New System.Net.Http.HttpClient With {.Timeout = TimeSpan.FromSeconds(120)}
                http.DefaultRequestHeaders.UserAgent.ParseAdd("Mozilla/5.0 (Windows NT 10.0; Win64; x64) IpConflictScanner/1.0")
                ' dernière version publiée
                Try
                    Dim html = Await http.GetStringAsync("https://npcap.com/dist/")
                    Dim best As Version = Nothing
                    For Each m As System.Text.RegularExpressions.Match In System.Text.RegularExpressions.Regex.Matches(html, "npcap-(\d+\.\d+)\.exe")
                        Dim v = New Version(m.Groups(1).Value)
                        If best Is Nothing OrElse v > best Then best = v
                    Next
                    If best IsNot Nothing Then url = $"https://npcap.com/dist/npcap-{best}.exe"
                Catch ex As Exception
                    Log("Liste des versions Npcap indisponible (" & ex.Message & "), version 1.88 utilisée.")
                End Try
                Log($"Téléchargement {url} ...")
                Dim bytes = Await http.GetByteArrayAsync(url)
                Dim exePath = Path.Combine(Path.GetTempPath(), Path.GetFileName(New Uri(url).LocalPath))
                System.IO.File.WriteAllBytes(exePath, bytes)

                ' contrôle de la signature Authenticode (éditeur Nmap Software)
                Dim signer As String
                Try
                    signer = System.Security.Cryptography.X509Certificates.X509Certificate.CreateFromSignedFile(exePath).Subject
                Catch
                    signer = ""
                End Try
                If signer.IndexOf("Nmap Software", StringComparison.OrdinalIgnoreCase) < 0 Then
                    Log($"[!] Signature inattendue ({If(signer = "", "aucune", signer)}) : installation annulée. Fichier : {exePath}")
                    Return
                End If
                Log($"Installateur signé par : {signer}. Lancement...")

                Using p = Process.Start(New ProcessStartInfo(exePath) With {.UseShellExecute = True})
                    If p IsNot Nothing Then Await p.WaitForExitAsync()
                End Using
            End Using

            If PcapArp.IsAvailable() Then
                chkPassive.Enabled = True
                btnNpcap.Visible = False
                Log("Npcap installé : écoute passive ARP disponible.")
            Else
                Log("Npcap toujours introuvable (installation annulée, ou redémarrer le programme).")
            End If
        Catch ex As Exception
            Log("Installation Npcap impossible : " & ex.Message & " — télécharger manuellement sur https://npcap.com/#download")
        Finally
            btnNpcap.Enabled = True
        End Try
    End Sub

    ' ================== Écoute passive ARP (Npcap) ==================

    Private Sub ChkPassive_Changed(sender As Object, e As EventArgs)
        If chkPassive.Checked Then
            If _currentIface Is Nothing Then chkPassive.Checked = False : Return
            Try
                _pcap = New PcapArp()
                AddHandler _pcap.PacketReceived, AddressOf Pcap_Packet
                AddHandler _pcap.Stopped, AddressOf Pcap_Stopped
                _pcap.Start(_currentIface)
                passiveTimer.Start()
                Log($"Écoute passive ARP démarrée sur {_currentIface.Name} : toutes les réponses ARP et les IP hors sous-réseau sont relevées.")
            Catch ex As Exception
                Log("Écoute passive impossible : " & ex.Message)
                StopPcap()
                chkPassive.Checked = False
            End Try
        Else
            StopPcap()
        End If
    End Sub

    Private Sub StopPcap()
        passiveTimer.Stop()
        If _pcap Is Nothing Then Return
        RemoveHandler _pcap.PacketReceived, AddressOf Pcap_Packet
        RemoveHandler _pcap.Stopped, AddressOf Pcap_Stopped
        _pcap.Dispose()
        _pcap = Nothing
        Log("Écoute passive ARP arrêtée.")
    End Sub

    ' thread de capture -> thread UI
    Private Sub Pcap_Packet(pkt As PcapArp.ArpPacket)
        If IsDisposed OrElse Not IsHandleCreated Then Return
        BeginInvoke(Sub() HandleArpPacket(pkt))
    End Sub

    Private Sub Pcap_Stopped(reason As String)
        If IsDisposed OrElse Not IsHandleCreated Then Return
        BeginInvoke(Sub()
                        If reason <> "arrêt demandé" Then
                            Log("Écoute passive interrompue : " & reason)
                            chkPassive.Checked = False
                        End If
                    End Sub)
    End Sub

    Private Sub HandleArpPacket(pkt As PcapArp.ArpPacket)
        Dim iface = _currentIface
        If iface Is Nothing OrElse pkt.IsProbe Then Return
        If pkt.SenderMac.Equals(iface.Mac, StringComparison.OrdinalIgnoreCase) Then Return
        Dim b0 = pkt.SenderIp.GetAddressBytes()(0)
        If b0 = 0 OrElse b0 >= 224 OrElse b0 = 127 Then Return
        Dim key = ToHostUInt(pkt.SenderIp)
        Dim mac = pkt.SenderMac
        Dim h As HostResult = Nothing
        If Not _hosts.TryGetValue(key, h) Then
            h = New HostResult With {.Ip = pkt.SenderIp, .Flags = HostFlags.Alive Or HostFlags.Passive}
            _hosts(key) = h
            _arpHistory(pkt.SenderIp.ToString()) = mac
            If iface.InSubnet(pkt.SenderIp) Then
                Log($"[NOUVEAU] {pkt.SenderIp} {mac} {_oui.Lookup(mac)} (écoute passive)")
            Else
                Log($"[HORS SOUS-RÉSEAU] {pkt.SenderIp} {mac} {_oui.Lookup(mac)} : IP incompatible avec {iface.Address}/{iface.PrefixLength}")
                System.Media.SystemSounds.Exclamation.Play()
            End If
        ElseIf h.Macs.Count > 0 AndAlso Not h.Macs.ContainsKey(mac) Then
            Dim alertKey = $"{pkt.SenderIp}|{mac}"
            If _alerted.Add(alertKey) Then
                Log($"[CONFLIT] {pkt.SenderIp} : {mac} ({_oui.Lookup(mac)}) répond aussi — déjà vue : {String.Join(", ", h.Macs.Keys)} (écoute passive{If(pkt.IsGratuitous, ", annonce gratuite", "")})")
                System.Media.SystemSounds.Exclamation.Play()
            End If
        End If
        h.AddMac(mac)
        h.Flags = h.Flags Or HostFlags.Passive
        h.LastSeen = DateTime.Now
        _dirty.Add(key)
    End Sub

    Private Sub PassiveTimer_Tick(sender As Object, e As EventArgs)
        If _dirty.Count = 0 OrElse _currentIface Is Nothing Then Return
        Scanner.Analyze(_hosts.Values.ToList(), _currentIface)
        lv.BeginUpdate()
        For Each k In _dirty
            Dim h As HostResult = Nothing
            If _hosts.TryGetValue(k, h) Then UpdateRow(h)
        Next
        For Each h In _hosts.Values.Where(Function(x) x.Severity > 0)
            UpdateRow(h)
        Next
        lv.EndUpdate()
        _dirty.Clear()
    End Sub

    Protected Overrides Sub OnFormClosing(e As FormClosingEventArgs)
        StopPcap()
        monitorTimer.Stop()
        _cts?.Cancel()
        MyBase.OnFormClosing(e)
    End Sub

End Class
