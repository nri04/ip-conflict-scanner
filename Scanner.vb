Imports System.Collections.Concurrent
Imports System.IO
Imports System.Net
Imports System.Net.NetworkInformation
Imports System.Net.Sockets
Imports System.Threading

''' <summary>Interface réseau IPv4 locale utilisable pour le scan.</summary>
Public Class LocalInterface
    Public Property Name As String
    Public Property Description As String
    Public Property IfIndex As Integer
    Public Property Address As IPAddress
    Public Property Mask As IPAddress
    Public Property Gateway As IPAddress
    Public Property Mac As String
    ''' <summary>GUID de l'interface ({...}), sert à retrouver le périphérique Npcap.</summary>
    Public Property Id As String
    Public Property DadState As DuplicateAddressDetectionState

    Public Function InSubnet(ip As IPAddress) As Boolean
        Dim m = ToHostUInt(Mask)
        Return (ToHostUInt(ip) And m) = (ToHostUInt(Address) And m)
    End Function

    Public ReadOnly Property PrefixLength As Integer
        Get
            Dim m = ToHostUInt(Mask)
            Dim n = 0
            While (m And &H80000000UI) <> 0
                n += 1
                m <<= 1
            End While
            Return n
        End Get
    End Property

    Public ReadOnly Property FirstHost As IPAddress
        Get
            Dim net = ToHostUInt(Address) And ToHostUInt(Mask)
            Return FromHostUInt(If(PrefixLength >= 31, net, net + 1UI))
        End Get
    End Property

    Public ReadOnly Property LastHost As IPAddress
        Get
            Dim bc = (ToHostUInt(Address) And ToHostUInt(Mask)) Or (Not ToHostUInt(Mask))
            Return FromHostUInt(If(PrefixLength >= 31, bc, bc - 1UI))
        End Get
    End Property

    Public Overrides Function ToString() As String
        Return $"{Name} — {Address}/{PrefixLength}  ({Description})"
    End Function

    Public Shared Function Enumerate() As List(Of LocalInterface)
        Dim list As New List(Of LocalInterface)
        For Each ni In NetworkInterface.GetAllNetworkInterfaces()
            If ni.OperationalStatus <> OperationalStatus.Up Then Continue For
            If ni.NetworkInterfaceType = NetworkInterfaceType.Loopback OrElse
               ni.NetworkInterfaceType = NetworkInterfaceType.Tunnel Then Continue For
            Dim props = ni.GetIPProperties()
            Dim v4 As IPv4InterfaceProperties = Nothing
            Try
                v4 = props.GetIPv4Properties()
            Catch
            End Try
            If v4 Is Nothing Then Continue For
            Dim gw = props.GatewayAddresses.
                Select(Function(g) g.Address).
                FirstOrDefault(Function(a) a.AddressFamily = AddressFamily.InterNetwork AndAlso Not a.Equals(IPAddress.Any))
            Dim macBytes = ni.GetPhysicalAddress().GetAddressBytes()
            For Each ua In props.UnicastAddresses
                If ua.Address.AddressFamily <> AddressFamily.InterNetwork Then Continue For
                If ua.IPv4Mask Is Nothing OrElse ua.IPv4Mask.Equals(IPAddress.Any) Then Continue For
                If ua.Address.GetAddressBytes()(0) = 169 AndAlso ua.Address.GetAddressBytes()(1) = 254 Then Continue For
                list.Add(New LocalInterface With {
                    .Name = ni.Name,
                    .Description = ni.Description,
                    .IfIndex = v4.Index,
                    .Address = ua.Address,
                    .Mask = ua.IPv4Mask,
                    .Gateway = gw,
                    .Mac = MacToString(macBytes, macBytes.Length),
                    .Id = ni.Id,
                    .DadState = ua.DuplicateAddressDetectionState
                })
            Next
        Next
        Return list
    End Function
End Class

<Flags>
Public Enum HostFlags
    None = 0
    Alive = 1
    IpConflict = 2          ' plusieurs MAC répondent pour la même IP
    SharedMac = 4           ' même MAC sur plusieurs IP (routeur, proxy ARP, VM, ou usurpation)
    MacChanged = 8          ' MAC modifiée pendant la surveillance
    LocalHost = 16          ' IP de ce PC
    Gateway = 32            ' passerelle par défaut
    RandomMac = 64          ' MAC administrée localement (aléatoire / privée)
    SelfConflict = 128      ' Windows signale l'IP locale en double (DAD)
    ArpOnly = 256           ' répond en ARP mais pas au ping (pare-feu)
    DualInterface = 512     ' les mêmes 2 MAC sont aussi en conflit sur une autre IP
    WrongSubnet = 1024      ' appareil vu en ARP avec une IP hors du sous-réseau
    Passive = 2048          ' vu par l'écoute passive ARP (Npcap)
    Reassigned = 4096       ' l'IP est passée d'un appareil à un autre (bail DHCP) : pas un conflit
End Enum

''' <summary>Période pendant laquelle une même MAC a été vue sans interruption pour une IP.</summary>
Public Class MacRun
    Public Property Mac As String
    Public Property Debut As DateTime
    Public Property Fin As DateTime
End Class

''' <summary>Résultat pour une IP.</summary>
Public Class HostResult
    Public Property Ip As IPAddress
    Public ReadOnly Property IpSort As UInteger
        Get
            Return ToHostUInt(Ip)
        End Get
    End Property
    ''' <summary>MAC observées -> nombre de fois vue.</summary>
    Public ReadOnly Property Macs As New ConcurrentDictionary(Of String, Integer)(StringComparer.OrdinalIgnoreCase)
    Public Property PingMs As Long = -1
    Public Property Hostname As String = ""
    Public Property Flags As HostFlags
    Public Property LastSeen As DateTime
    Public Property Notes As String = ""
    ''' <summary>Notes calculées par l'analyse globale (recalculées à chaque analyse).</summary>
    Public Property AnalysisNotes As String = ""

    ''' <summary>Notes d'observation + notes d'analyse.</summary>
    Public ReadOnly Property AllNotes As String
        Get
            Return String.Join(" ; ", {Notes, AnalysisNotes}.Where(Function(n) n <> ""))
        End Get
    End Property

    Public Sub AddAnalysisNote(note As String)
        If AnalysisNotes.Contains(note) Then Return
        AnalysisNotes = If(AnalysisNotes = "", note, AnalysisNotes & " ; " & note)
    End Sub

    ''' <summary>Paires "1ère réponse / dernière réponse" différentes = 2 répondeurs simultanés.</summary>
    Public ReadOnly Property ResponderPairs As New ConcurrentDictionary(Of String, Integer)(StringComparer.OrdinalIgnoreCase)

    ''' <summary>
    ''' Une MAC qui revient sur l'IP après une autre MAC dans ce délai (A → B → A) = conflit.
    ''' Au-delà, ou si l'ancienne MAC ne revient pas, c'est une réattribution (bail DHCP), pas un conflit.
    ''' </summary>
    Public Shared ReadOnly AlternanceMax As TimeSpan = TimeSpan.FromMinutes(10)

    ''' <summary>Nombre max de périodes gardées par IP (surveillance longue).</summary>
    Private Const MaxRuns As Integer = 200

    Private ReadOnly _runsLock As New Object()
    ''' <summary>Historique chronologique des MAC vues pour cette IP.</summary>
    Private ReadOnly _runs As New List(Of MacRun)

    Public Sub AddMac(mac As String, Optional quand As DateTime = Nothing)
        If String.IsNullOrEmpty(mac) Then Return
        If quand = DateTime.MinValue Then quand = DateTime.Now
        Macs.AddOrUpdate(mac, 1, Function(k, v) v + 1)
        RecordRun(mac, quand)
        UpdateConflict()
    End Sub

    ''' <summary>Enregistre une sonde ARP : 1ère réponse (SendARP) et dernière (cache Windows).</summary>
    ''' <returns>True si deux MAC différentes ont répondu à la même requête.</returns>
    Public Function AddProbe(firstMac As String, lastMac As String) As Boolean
        Dim quand = DateTime.Now
        If String.IsNullOrEmpty(firstMac) OrElse String.IsNullOrEmpty(lastMac) OrElse
           firstMac.Equals(lastMac, StringComparison.OrdinalIgnoreCase) Then
            AddMac(If(String.IsNullOrEmpty(firstMac), lastMac, firstMac), quand)
            Return False
        End If
        ' deux machines ont répondu à la MÊME requête : conflit certain
        ResponderPairs.AddOrUpdate($"1ère={firstMac} / dernière={lastMac}", 1, Function(k, v) v + 1)
        Macs.AddOrUpdate(firstMac, 1, Function(k, v) v + 1)
        Macs.AddOrUpdate(lastMac, 1, Function(k, v) v + 1)
        RecordRun(firstMac, quand)
        RecordRun(lastMac, quand)
        UpdateConflict()
        Return True
    End Function

    Private Sub RecordRun(mac As String, quand As DateTime)
        SyncLock _runsLock
            Dim last = If(_runs.Count > 0, _runs(_runs.Count - 1), Nothing)
            If last IsNot Nothing AndAlso last.Mac.Equals(mac, StringComparison.OrdinalIgnoreCase) Then
                If quand > last.Fin Then last.Fin = quand
            Else
                _runs.Add(New MacRun With {.Mac = mac, .Debut = quand, .Fin = quand})
                If _runs.Count > MaxRuns Then _runs.RemoveRange(0, _runs.Count - MaxRuns)
            End If
        End SyncLock
    End Sub

    ''' <summary>
    ''' Conflit = 2 répondeurs à la même requête, ou alternance A → B → A en moins de AlternanceMax.
    ''' Plusieurs MAC qui se succèdent sans retour = IP réattribuée (pas d'alerte).
    ''' </summary>
    Public Sub UpdateConflict()
        Dim conflit = Not ResponderPairs.IsEmpty
        Dim changements As Integer
        SyncLock _runsLock
            changements = _runs.Count - 1
            If Not conflit Then
                For i = 0 To _runs.Count - 3
                    For j = i + 2 To _runs.Count - 1
                        If _runs(j).Debut - _runs(i).Fin > AlternanceMax Then Exit For
                        If _runs(j).Mac.Equals(_runs(i).Mac, StringComparison.OrdinalIgnoreCase) Then
                            conflit = True
                            Exit For
                        End If
                    Next
                    If conflit Then Exit For
                Next
            End If
        End SyncLock
        If conflit Then
            Flags = (Flags Or HostFlags.IpConflict) And Not HostFlags.Reassigned
        ElseIf changements > 0 Then
            Flags = (Flags Or HostFlags.Reassigned) And Not HostFlags.IpConflict
        Else
            Flags = Flags And Not (HostFlags.IpConflict Or HostFlags.Reassigned)
        End If
    End Sub

    ''' <summary>Reprend l'historique d'un ancien résultat pour la même IP (fusion chronologique).</summary>
    Public Sub MergeFrom(other As HostResult)
        If other Is Nothing OrElse ReferenceEquals(other, Me) Then Return
        For Each kv In other.Macs
            Macs.AddOrUpdate(kv.Key, kv.Value, Function(k, v) v + kv.Value)
        Next
        For Each kv In other.ResponderPairs
            ResponderPairs.AddOrUpdate(kv.Key, kv.Value, Function(k, v) v + kv.Value)
        Next
        Dim autres As List(Of MacRun)
        SyncLock other._runsLock
            autres = other._runs.Select(Function(r) New MacRun With {.Mac = r.Mac, .Debut = r.Debut, .Fin = r.Fin}).ToList()
        End SyncLock
        SyncLock _runsLock
            Dim tous = autres.Concat(_runs).OrderBy(Function(r) r.Debut).ToList()
            _runs.Clear()
            For Each r In tous
                Dim last = If(_runs.Count > 0, _runs(_runs.Count - 1), Nothing)
                If last IsNot Nothing AndAlso last.Mac.Equals(r.Mac, StringComparison.OrdinalIgnoreCase) Then
                    If r.Fin > last.Fin Then last.Fin = r.Fin
                Else
                    _runs.Add(r)
                End If
            Next
            If _runs.Count > MaxRuns Then _runs.RemoveRange(0, _runs.Count - MaxRuns)
        End SyncLock
        UpdateConflict()
    End Sub

    ''' <summary>Dernière MAC vue pour cette IP.</summary>
    Public ReadOnly Property CurrentMac As String
        Get
            SyncLock _runsLock
                Return If(_runs.Count > 0, _runs(_runs.Count - 1).Mac, Nothing)
            End SyncLock
        End Get
    End Property

    ''' <summary>MAC qui ont précédé la MAC actuelle (IP réattribuée), la plus récente d'abord.</summary>
    Public ReadOnly Property PreviousMacs As List(Of String)
        Get
            Dim cur = CurrentMac
            SyncLock _runsLock
                Return _runs.AsEnumerable().Reverse().Select(Function(r) r.Mac).
                    Where(Function(m) Not m.Equals(cur, StringComparison.OrdinalIgnoreCase)).
                    Distinct(StringComparer.OrdinalIgnoreCase).ToList()
            End SyncLock
        End Get
    End Property

    ''' <summary>MAC réellement présentes : la seule MAC actuelle si l'IP a été réattribuée, sinon toutes.</summary>
    Public ReadOnly Property ActiveMacs As IEnumerable(Of String)
        Get
            If Flags.HasFlag(HostFlags.Reassigned) AndAlso CurrentMac IsNot Nothing Then Return {CurrentMac}
            Return Macs.Keys.ToList()
        End Get
    End Property

    Public ReadOnly Property ResponderText As String
        Get
            If ResponderPairs.IsEmpty Then Return ""
            Return "2 répondeurs : " & String.Join(" ; ", ResponderPairs.Select(Function(kv) $"{kv.Key} (x{kv.Value})"))
        End Get
    End Property

    Public ReadOnly Property MacList As String
        Get
            ' IP réattribuée : seule la MAC actuelle est affichée (les précédentes vont dans les notes)
            If Flags.HasFlag(HostFlags.Reassigned) AndAlso CurrentMac IsNot Nothing Then Return CurrentMac
            Return String.Join(" | ", Macs.OrderByDescending(Function(kv) kv.Value).
                Select(Function(kv) If(Macs.Count > 1, $"{kv.Key} (x{kv.Value})", kv.Key)))
        End Get
    End Property

    ''' <summary>MAC de référence : la dernière vue (ou la plus fréquente à défaut d'historique).</summary>
    Public ReadOnly Property PrimaryMac As String
        Get
            Dim cur = CurrentMac
            If cur IsNot Nothing Then Return cur
            Return Macs.OrderByDescending(Function(kv) kv.Value).Select(Function(kv) kv.Key).FirstOrDefault()
        End Get
    End Property

    Public ReadOnly Property StatusText As String
        Get
            Dim s As New List(Of String)
            If Flags.HasFlag(HostFlags.SelfConflict) Then s.Add("CONFLIT IP AVEC CE PC")
            If Flags.HasFlag(HostFlags.IpConflict) Then s.Add($"CONFLIT : {Macs.Count} MAC")
            If Flags.HasFlag(HostFlags.WrongSubnet) Then s.Add("HORS RÉSEAU")
            If Flags.HasFlag(HostFlags.MacChanged) Then s.Add("MAC CHANGÉE")
            If Flags.HasFlag(HostFlags.SharedMac) Then s.Add("MAC multi-IP")
            If Flags.HasFlag(HostFlags.Reassigned) Then s.Add("IP réattribuée")
            If Flags.HasFlag(HostFlags.LocalHost) Then s.Add("Ce PC")
            If Flags.HasFlag(HostFlags.Gateway) Then s.Add("Passerelle")
            If Flags.HasFlag(HostFlags.RandomMac) Then s.Add("MAC aléatoire")
            If Flags.HasFlag(HostFlags.ArpOnly) Then s.Add("Ping bloqué")
            If s.Count = 0 Then s.Add("OK")
            Return String.Join(", ", s)
        End Get
    End Property

    Public ReadOnly Property Severity As Integer
        Get
            If (Flags And (HostFlags.IpConflict Or HostFlags.SelfConflict Or HostFlags.MacChanged)) <> 0 Then Return 2
            If (Flags And (HostFlags.SharedMac Or HostFlags.WrongSubnet)) <> 0 Then Return 1
            Return 0
        End Get
    End Property
End Class

Public Class ScanOptions
    Public Property Iface As LocalInterface
    Public Property StartIp As IPAddress
    Public Property EndIp As IPAddress
    Public Property Passes As Integer = 6
    Public Property PingTimeoutMs As Integer = 600
    Public Property Parallelism As Integer = 64
    Public Property ResolveNames As Boolean = True
    Public Property PurgeArpCache As Boolean = True
End Class

Public Class ScanProgress
    Public Property Done As Integer
    Public Property Total As Integer
    Public Property Host As HostResult
    Public Property Message As String
End Class

''' <summary>Moteur de scan : ping + ARP multi-passes avec purge du cache entre passes.</summary>
Public Class Scanner

    Public Shared Async Function RunAsync(opt As ScanOptions, progress As IProgress(Of ScanProgress), ct As CancellationToken) As Task(Of List(Of HostResult))
        Dim startU = ToHostUInt(opt.StartIp)
        Dim endU = ToHostUInt(opt.EndIp)
        If endU < startU Then
            Dim t = startU : startU = endU : endU = t
        End If
        Dim total = CInt(endU - startU + 1UI)
        Dim results As New ConcurrentDictionary(Of UInteger, HostResult)
        Dim done = 0
        Dim canPurge = opt.PurgeArpCache AndAlso IsAdmin()
        If opt.PurgeArpCache AndAlso Not canPurge Then
            progress?.Report(New ScanProgress With {.Message = "[!] Pas admin : purge ARP impossible, détection des conflits dégradée."})
        End If

        ' Étape 1 : ping en parallèle (sans SendARP). Le ping déclenche la résolution ARP de Windows,
        ' y compris pour les hôtes qui bloquent l'ICMP.
        Using sem As New SemaphoreSlim(opt.Parallelism)
            Dim tasks As New List(Of Task)
            For u = startU To endU
                ct.ThrowIfCancellationRequested()
                Dim ipU = u
                Await sem.WaitAsync(ct)
                tasks.Add(Task.Run(Async Function()
                                       Try
                                           Dim h = Await PingAsync(FromHostUInt(ipU), opt)
                                           If h IsNot Nothing Then results(ipU) = h
                                           Dim d = Interlocked.Increment(done)
                                           progress?.Report(New ScanProgress With {.Done = d, .Total = total * 2, .Host = h})
                                       Finally
                                           sem.Release()
                                       End Try
                                   End Function, ct))
                If u = UInteger.MaxValue Then Exit For
            Next
            Await Task.WhenAll(tasks)
        End Using

        ' Étape 2 : table ARP Windows -> MAC de chaque hôte + hôtes qui bloquent le ping
        For Each e In ReadArpTable(opt.Iface.IfIndex)
            Dim u = ToHostUInt(e.Ip)
            If u < startU OrElse u > endU Then Continue For
            Dim isNew = Not results.ContainsKey(u)
            Dim h = results.GetOrAdd(u, Function(k) New HostResult With {.Ip = e.Ip, .LastSeen = DateTime.Now})
            If isNew Then h.Flags = h.Flags Or HostFlags.Alive Or HostFlags.ArpOnly
            h.AddMac(e.Mac)
            If e.IsStatic Then
                h.Notes = "ARP statique"
            ElseIf isNew Then
                h.Notes = "cache ARP seul"
            End If
            progress?.Report(New ScanProgress With {.Host = h})
        Next
        Dim local As HostResult = Nothing
        If results.TryGetValue(ToHostUInt(opt.Iface.Address), local) Then local.AddMac(opt.Iface.Mac)

        ' Étape 3 : noms DNS en parallèle
        If opt.ResolveNames Then
            Await Task.WhenAll(results.Values.Where(Function(x) x.Hostname = "").Select(Function(x) ResolveNameAsync(x, ct)))
        End If

        ' Étape 4 : sondes ARP doubles, STRICTEMENT une à la fois (SendARP en parallèle mélange les réponses entre IP)
        Dim found = results.Values.Where(Function(x) Not x.Flags.HasFlag(HostFlags.LocalHost)).OrderBy(Function(x) x.IpSort).ToList()
        If opt.Passes > 0 AndAlso found.Count > 0 Then
            progress?.Report(New ScanProgress With {.Done = total, .Total = total * 2, .Message = $"{found.Count} hôtes. {opt.Passes} passe(s) ARP séquentielle(s)..."})
            Dim steps = found.Count * opt.Passes
            Dim stepDone = 0
            Await Task.Run(Sub()
                               Dim rnd As New Random()
                               For p = 1 To opt.Passes
                                   For Each host In found
                                       ct.ThrowIfCancellationRequested()
                                       Dim r = ProbeArpPair(opt.Iface, host.Ip, canPurge)
                                       stepDone += 1
                                       If r.First <> "" Then
                                           Dim etaitConflit = host.Flags.HasFlag(HostFlags.IpConflict)
                                           Dim dual = host.AddProbe(r.First, r.Last)
                                           If dual Then
                                               progress?.Report(New ScanProgress With {.Host = host, .Message = $"[CONFLIT] {host.Ip} : 2 MAC ont répondu (1ère {r.First}, dernière {r.Last})"})
                                           ElseIf Not etaitConflit AndAlso host.Flags.HasFlag(HostFlags.IpConflict) Then
                                               progress?.Report(New ScanProgress With {.Host = host, .Message = $"[CONFLIT] {host.Ip} : MAC qui alternent ({host.MacList})"})
                                           End If
                                       End If
                                       progress?.Report(New ScanProgress With {.Done = total + CInt(CLng(total) * stepDone \ steps), .Total = total * 2})
                                   Next
                                   Thread.Sleep(100 + rnd.Next(250)) ' décale les passes
                               Next
                           End Sub, ct)
        End If

        Dim list = results.Values.OrderBy(Function(h) h.IpSort).ToList()
        Analyze(list, opt.Iface)
        progress?.Report(New ScanProgress With {.Done = total * 2, .Total = total * 2})
        Return list
    End Function

    ''' <summary>Délai d'attente des réponses ARP tardives avant lecture du cache (ms).</summary>
    Public Const LateReplyWaitMs As Integer = 250

    ''' <summary>Verrou global : une seule sonde ARP à la fois dans tout le programme.</summary>
    Private Shared ReadOnly ArpLock As New Object()

    ''' <summary>
    ''' Sonde ARP double : SendARP renvoie la 1ère réponse reçue, le cache Windows garde la dernière.
    ''' Si les deux MAC diffèrent, deux machines ont répondu pour la même IP = conflit.
    ''' Sérialisée : des SendARP simultanés renvoient des MAC d'autres IP (faux conflits).
    ''' </summary>
    Public Shared Function ProbeArpPair(iface As LocalInterface, ip As IPAddress, canPurge As Boolean) As (First As String, Last As String)
        SyncLock ArpLock
            If canPurge Then ArpDeleteEntry(iface.IfIndex, ip)
            Dim first = ArpResolve(ip, iface.Address)
            If first = "" Then Return (first, "")
            Thread.Sleep(LateReplyWaitMs)
            Dim last = ReadArpEntry(iface.IfIndex, ip)
            Return (first, last)
        End SyncLock
    End Function

    ''' <summary>Ping simple (aucun appel SendARP ici).</summary>
    Private Shared Async Function PingAsync(ip As IPAddress, opt As ScanOptions) As Task(Of HostResult)
        Dim h As New HostResult With {.Ip = ip}
        If ip.Equals(opt.Iface.Address) Then
            h.AddMac(opt.Iface.Mac)
            h.Flags = h.Flags Or HostFlags.LocalHost Or HostFlags.Alive
            h.PingMs = 0
            h.Hostname = Dns.GetHostName()
            h.LastSeen = DateTime.Now
            Return h
        End If
        Try
            Using p As New Ping()
                Dim r = Await p.SendPingAsync(ip, opt.PingTimeoutMs)
                If r.Status = IPStatus.Success Then
                    h.PingMs = r.RoundtripTime
                    h.Flags = h.Flags Or HostFlags.Alive
                    h.LastSeen = DateTime.Now
                    Return h
                End If
            End Using
        Catch
        End Try
        Return Nothing
    End Function

    Private Const DnsTimeoutMs As Integer = 4000
    Private Const NameQueryTimeoutMs As Integer = 1500

    ''' <summary>Nom d'hôte : DNS (box), puis NetBIOS (PC Windows, NAS), puis mDNS (Apple, Android, Linux, ESPHome, imprimantes).</summary>
    Private Shared Async Function ResolveNameAsync(h As HostResult, ct As CancellationToken) As Task
        Try
            Dim dnsTask = Dns.GetHostEntryAsync(h.Ip)
            If Await Task.WhenAny(dnsTask, Task.Delay(DnsTimeoutMs, ct)) Is dnsTask AndAlso dnsTask.Status = TaskStatus.RanToCompletion Then
                Dim n = dnsTask.Result.HostName
                If n <> h.Ip.ToString() Then h.Hostname = n
            End If
        Catch
        End Try
        If h.Hostname <> "" Then Return
        Try
            Dim nb = Await NetBiosNameAsync(h.Ip, ct)
            If nb <> "" Then h.Hostname = nb : Return
        Catch
        End Try
        Try
            Dim md = Await MdnsNameAsync(h.Ip, ct)
            If md <> "" Then h.Hostname = md
        Catch
        End Try
    End Function

    ''' <summary>Envoie une requête UDP et attend une réponse (ou "Nothing" après le délai).</summary>
    Private Shared Async Function UdpQueryAsync(ip As IPAddress, port As Integer, query As Byte(), ct As CancellationToken) As Task(Of Byte())
        Using udp As New UdpClient(AddressFamily.InterNetwork)
            Await udp.SendAsync(query, query.Length, New IPEndPoint(ip, port))
            Dim rx = udp.ReceiveAsync()
            If Await Task.WhenAny(rx, Task.Delay(NameQueryTimeoutMs, ct)) Is rx AndAlso rx.Status = TaskStatus.RanToCompletion Then
                Return rx.Result.Buffer
            End If
            Return Nothing
        End Using
    End Function

    ''' <summary>Requête NetBIOS NBSTAT (UDP 137) : nom de poste (suffixe 0x00, nom unique).</summary>
    Private Shared Async Function NetBiosNameAsync(ip As IPAddress, ct As CancellationToken) As Task(Of String)
        Dim q As New List(Of Byte) From {&H13, &H37, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, &H20}
        Dim nameBytes(15) As Byte
        nameBytes(0) = AscW("*"c)
        For Each b In nameBytes
            q.Add(CByte(&H41 + (b >> 4)))
            q.Add(CByte(&H41 + (b And &HF)))
        Next
        q.AddRange(New Byte() {0, 0, &H21, 0, 1})
        Dim r = Await UdpQueryAsync(ip, 137, q.ToArray(), ct)
        If r Is Nothing OrElse r.Length < 57 Then Return ""
        Dim count = r(56)
        For i = 0 To count - 1
            Dim off = 57 + i * 18
            If off + 18 > r.Length Then Exit For
            Dim suffix = r(off + 15)
            Dim isGroup = (r(off + 16) And &H80) <> 0
            If suffix = 0 AndAlso Not isGroup Then
                Return System.Text.Encoding.ASCII.GetString(r, off, 15).Trim().TrimEnd(ChrW(0))
            End If
        Next
        Return ""
    End Function

    ''' <summary>Requête mDNS PTR inverse envoyée directement à l'appareil (UDP 5353) : "nom.local" → "nom".</summary>
    Private Shared Async Function MdnsNameAsync(ip As IPAddress, ct As CancellationToken) As Task(Of String)
        Dim b = ip.GetAddressBytes()
        Dim labels = {b(3).ToString(), b(2).ToString(), b(1).ToString(), b(0).ToString(), "in-addr", "arpa"}
        Dim q As New List(Of Byte) From {0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
        For Each l In labels
            q.Add(CByte(l.Length))
            q.AddRange(System.Text.Encoding.ASCII.GetBytes(l))
        Next
        q.AddRange(New Byte() {0, 0, 12, 0, 1})
        Dim r = Await UdpQueryAsync(ip, 5353, q.ToArray(), ct)
        If r Is Nothing OrElse r.Length < 12 Then Return ""
        Dim qd = (CInt(r(4)) << 8) Or r(5)
        Dim an = (CInt(r(6)) << 8) Or r(7)
        Dim pos = 12
        For i = 1 To qd
            ReadDnsName(r, pos, pos)
            pos += 4
        Next
        For i = 1 To an
            ReadDnsName(r, pos, pos)
            If pos + 10 > r.Length Then Exit For
            Dim rtype = (CInt(r(pos)) << 8) Or r(pos + 1)
            Dim rdlen = (CInt(r(pos + 8)) << 8) Or r(pos + 9)
            pos += 10
            If rtype = 12 Then
                Dim dummy As Integer
                Dim n = ReadDnsName(r, pos, dummy)
                If n.EndsWith(".local", StringComparison.OrdinalIgnoreCase) Then n = n.Substring(0, n.Length - 6)
                Return n
            End If
            pos += rdlen
        Next
        Return ""
    End Function

    ''' <summary>Lit un nom DNS (avec pointeurs de compression). nextPos = position après le nom.</summary>
    Private Shared Function ReadDnsName(buf As Byte(), start As Integer, ByRef nextPos As Integer) As String
        Dim parts As New List(Of String)
        Dim pos = start
        Dim jumped = False
        Dim guard = 0
        nextPos = start
        While pos < buf.Length AndAlso guard < 64
            guard += 1
            Dim len = buf(pos)
            If len = 0 Then
                If Not jumped Then nextPos = pos + 1
                Exit While
            End If
            If (len And &HC0) = &HC0 Then
                If pos + 1 >= buf.Length Then Exit While
                If Not jumped Then nextPos = pos + 2
                pos = ((len And &H3F) << 8) Or buf(pos + 1)
                jumped = True
                Continue While
            End If
            If pos + 1 + len > buf.Length Then Exit While
            parts.Add(System.Text.Encoding.UTF8.GetString(buf, pos + 1, len))
            pos += 1 + len
        End While
        Return String.Join(".", parts)
    End Function

    ''' <summary>IP courte pour les notes : ".91" dans le même /24 que l'interface, sinon l'IP complète.</summary>
    Private Shared Function Court(ip As IPAddress, iface As LocalInterface) As String
        If (ToHostUInt(ip) And &HFFFFFF00UI) = (ToHostUInt(iface.Address) And &HFFFFFF00UI) Then Return "." & (ToHostUInt(ip) And &HFFUI).ToString()
        Return ip.ToString()
    End Function

    ''' <summary>Analyse globale : MAC partagées, passerelle, MAC aléatoires, conflit avec ce PC.</summary>
    Public Shared Sub Analyze(list As List(Of HostResult), iface As LocalInterface)
        Dim macToIps As New Dictionary(Of String, List(Of HostResult))(StringComparer.OrdinalIgnoreCase)
        ' les indicateurs et notes d'analyse sont recalculés entièrement (pas d'alerte qui reste après correction)
        For Each h In list
            h.Flags = h.Flags And Not (HostFlags.SharedMac Or HostFlags.DualInterface Or HostFlags.RandomMac)
            h.AnalysisNotes = ""
        Next
        For Each h In list
            For Each m In h.ActiveMacs
                If Not macToIps.ContainsKey(m) Then macToIps(m) = New List(Of HostResult)
                macToIps(m).Add(h)
            Next
            If iface.Gateway IsNot Nothing AndAlso h.Ip.Equals(iface.Gateway) Then h.Flags = h.Flags Or HostFlags.Gateway
            If h.Ip.Equals(iface.Address) Then
                h.Flags = h.Flags Or HostFlags.LocalHost
                If iface.DadState = DuplicateAddressDetectionState.Duplicate Then h.Flags = h.Flags Or HostFlags.SelfConflict
                ' une MAC étrangère vue pour notre propre IP = conflit
                If h.Macs.Keys.Any(Function(m) Not m.Equals(iface.Mac, StringComparison.OrdinalIgnoreCase)) Then
                    h.Flags = h.Flags Or HostFlags.SelfConflict Or HostFlags.IpConflict
                End If
            End If
            Dim pm = h.PrimaryMac
            If pm IsNot Nothing AndAlso (Convert.ToByte(pm.Substring(0, 2), 16) And &H2) <> 0 Then
                h.Flags = h.Flags Or HostFlags.RandomMac
            End If
            If Not iface.InSubnet(h.Ip) Then
                h.Flags = h.Flags Or HostFlags.WrongSubnet
                Dim n = $"hors {FromHostUInt(ToHostUInt(iface.Address) And ToHostUInt(iface.Mask))}/{iface.PrefixLength}"
                h.AddAnalysisNote(n)
            End If
        Next

        ' IP réattribuée : indique la MAC précédente et où elle se trouve maintenant
        For Each h In list
            If Not h.Flags.HasFlag(HostFlags.Reassigned) Then Continue For
            For Each m In h.PreviousMacs.Take(2)
                Dim ailleurs As List(Of HostResult) = Nothing
                Dim ou = ""
                If macToIps.TryGetValue(m, ailleurs) Then
                    Dim autres = ailleurs.Where(Function(x) Not ReferenceEquals(x, h)).Select(Function(x) Court(x.Ip, iface)).ToList()
                    If autres.Count > 0 Then ou = " → " & String.Join(" ", autres)
                End If
                Dim note = $"avant : {m}{ou}"
                h.AddAnalysisNote(note)
            Next
        Next

        ' Appareil double interface : la même paire de MAC est en conflit sur plusieurs IP
        Dim pairMap As New Dictionary(Of String, List(Of HostResult))(StringComparer.OrdinalIgnoreCase)
        For Each h In list
            If h.Macs.Count <> 2 OrElse Not h.Flags.HasFlag(HostFlags.IpConflict) Then Continue For
            Dim k = String.Join(" + ", h.Macs.Keys.OrderBy(Function(m) m, StringComparer.OrdinalIgnoreCase))
            If Not pairMap.ContainsKey(k) Then pairMap(k) = New List(Of HostResult)
            pairMap(k).Add(h)
        Next
        For Each kv In pairMap
            If kv.Value.Count < 2 Then Continue For
            For Each h In kv.Value
                h.Flags = h.Flags Or HostFlags.DualInterface
                Dim note = "aussi " & String.Join(" ", kv.Value.Where(Function(x) Not ReferenceEquals(x, h)).Select(Function(x) Court(x.Ip, iface)))
                h.AddAnalysisNote(note)
            Next
        Next

        For Each kv In macToIps
            ' MAC partagée déjà expliquée par un appareil double interface : pas d'alerte en plus
            If kv.Value.All(Function(x) x.Flags.HasFlag(HostFlags.DualInterface)) Then Continue For
            If kv.Value.Count > 1 Then
                For Each h In kv.Value
                    h.Flags = h.Flags Or HostFlags.SharedMac
                    Dim note = "aussi " & String.Join(" ", kv.Value.Where(Function(x) Not ReferenceEquals(x, h)).Select(Function(x) Court(x.Ip, iface)))
                    h.AddAnalysisNote(note)
                Next
            End If
        Next
    End Sub

End Class

''' <summary>Base OUI fabricants (fichier IEEE oui.csv optionnel à côté de l'exe).</summary>
Public Class OuiDatabase
    Private ReadOnly _map As New Dictionary(Of String, String)(StringComparer.OrdinalIgnoreCase)

    Public ReadOnly Property Count As Integer
        Get
            Return _map.Count
        End Get
    End Property

    Public Sub New()
        ' Quelques préfixes courants intégrés (base complète : oui.csv IEEE à côté de l'exe)
        Dim builtin = New String() {
            "B827EB=Raspberry Pi", "DCA632=Raspberry Pi", "E45F01=Raspberry Pi", "2CCF67=Raspberry Pi", "D83ADD=Raspberry Pi",
            "000C29=VMware", "005056=VMware", "080027=VirtualBox", "00155D=Hyper-V", "525400=QEMU/KVM",
            "246F28=Espressif", "24A160=Espressif", "30AEA4=Espressif", "3C71BF=Espressif", "84CCA8=Espressif",
            "A4CF12=Espressif", "BCDDC2=Espressif", "CC50E3=Espressif", "ECFABC=Espressif",
            "24A43C=Ubiquiti", "788A20=Ubiquiti", "FCECDA=Ubiquiti", "F09FC2=Ubiquiti", "B4FBE4=Ubiquiti", "E063DA=Ubiquiti",
            "F4CAE5=Freebox", "0024D4=Freebox", "8C97EA=Freebox", "68A378=Freebox",
            "3810D5=AVM", "C80E14=AVM", "001132=Synology", "001788=Philips Hue", "000E58=Sonos", "5CAAFD=Sonos",
            "00000C=Cisco"
        }
        For Each line In builtin
            Dim p = line.Split("="c)
            If p(0).Length = 6 Then _map(p(0)) = p(1)
        Next
    End Sub

    ''' <summary>Charge le CSV IEEE (https://standards-oui.ieee.org/oui/oui.csv) : Registry,Assignment,Organization Name,...</summary>
    Public Function LoadCsv(path As String) As Integer
        If Not File.Exists(path) Then Return 0
        Dim n = 0
        For Each line In File.ReadLines(path)
            If line.StartsWith("Registry", StringComparison.OrdinalIgnoreCase) Then Continue For
            Dim fields = ParseCsvLine(line)
            If fields.Count < 3 Then Continue For
            Dim key = fields(1).Trim().ToUpperInvariant()
            If key.Length < 6 Then Continue For
            _map(key) = fields(2).Trim()
            n += 1
        Next
        Return n
    End Function

    Private Shared Function ParseCsvLine(line As String) As List(Of String)
        Dim res As New List(Of String)
        Dim sb As New Text.StringBuilder()
        Dim inQ = False
        For i = 0 To line.Length - 1
            Dim c = line(i)
            If c = """"c Then
                If inQ AndAlso i + 1 < line.Length AndAlso line(i + 1) = """"c Then
                    sb.Append(""""c) : i += 1
                Else
                    inQ = Not inQ
                End If
            ElseIf c = ","c AndAlso Not inQ Then
                res.Add(sb.ToString()) : sb.Clear()
            Else
                sb.Append(c)
            End If
        Next
        res.Add(sb.ToString())
        Return res
    End Function

    Public Function Lookup(mac As String) As String
        If String.IsNullOrEmpty(mac) Then Return ""
        Dim hex = mac.Replace(":", "").Replace("-", "").ToUpperInvariant()
        If hex.Length < 6 Then Return ""
        ' MA-S (36 bits) / MA-M (28 bits) puis MA-L (24 bits)
        Dim v As String = Nothing
        If hex.Length >= 9 AndAlso _map.TryGetValue(hex.Substring(0, 9), v) Then Return v
        If hex.Length >= 7 AndAlso _map.TryGetValue(hex.Substring(0, 7), v) Then Return v
        If _map.TryGetValue(hex.Substring(0, 6), v) Then Return v
        If (Convert.ToByte(hex.Substring(0, 2), 16) And &H2) <> 0 Then Return "(MAC locale/aléatoire)"
        Return ""
    End Function
End Class
