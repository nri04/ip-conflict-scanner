Imports System.IO
Imports System.Net
Imports System.Runtime.InteropServices
Imports System.Text
Imports System.Threading

''' <summary>
''' Écoute passive des trames ARP via Npcap (wpcap.dll), sans dépendance NuGet.
''' Voit toutes les réponses (pas seulement la 1ère/dernière) et les appareils hors sous-réseau.
''' </summary>
Public NotInheritable Class PcapArp
    Implements IDisposable

    <StructLayout(LayoutKind.Sequential)>
    Private Structure pcap_if
        Public [next] As IntPtr
        Public name As IntPtr
        Public description As IntPtr
        Public addresses As IntPtr
        Public flags As UInteger
    End Structure

    <StructLayout(LayoutKind.Sequential)>
    Private Structure bpf_program
        Public bf_len As UInteger
        Public bf_insns As IntPtr
    End Structure

    <DllImport("kernel32.dll", CharSet:=CharSet.Unicode, SetLastError:=True)>
    Private Shared Function SetDllDirectory(path As String) As Boolean
    End Function

    <DllImport("wpcap.dll", CharSet:=CharSet.Ansi)>
    Private Shared Function pcap_findalldevs(ByRef alldevs As IntPtr, errbuf As StringBuilder) As Integer
    End Function
    <DllImport("wpcap.dll")>
    Private Shared Sub pcap_freealldevs(alldevs As IntPtr)
    End Sub
    <DllImport("wpcap.dll", CharSet:=CharSet.Ansi)>
    Private Shared Function pcap_open_live(device As String, snaplen As Integer, promisc As Integer, to_ms As Integer, errbuf As StringBuilder) As IntPtr
    End Function
    <DllImport("wpcap.dll", CharSet:=CharSet.Ansi)>
    Private Shared Function pcap_compile(p As IntPtr, ByRef fp As bpf_program, str As String, optimize As Integer, netmask As UInteger) As Integer
    End Function
    <DllImport("wpcap.dll")>
    Private Shared Function pcap_setfilter(p As IntPtr, ByRef fp As bpf_program) As Integer
    End Function
    <DllImport("wpcap.dll")>
    Private Shared Sub pcap_freecode(ByRef fp As bpf_program)
    End Sub
    <DllImport("wpcap.dll")>
    Private Shared Function pcap_next_ex(p As IntPtr, ByRef pkt_header As IntPtr, ByRef pkt_data As IntPtr) As Integer
    End Function
    <DllImport("wpcap.dll")>
    Private Shared Sub pcap_close(p As IntPtr)
    End Sub

    Private Shared _dllDirSet As Boolean

    ''' <summary>Trame ARP reçue : expéditeur (IP, MAC), cible, type.</summary>
    Public Class ArpPacket
        Public Property SenderIp As IPAddress
        Public Property SenderMac As String
        Public Property TargetIp As IPAddress
        Public Property IsReply As Boolean
        Public Property IsProbe As Boolean      ' IP expéditeur 0.0.0.0 (détection de doublon par l'appareil)
        Public Property IsGratuitous As Boolean ' annonce de sa propre IP
    End Class

    Public Event PacketReceived(pkt As ArpPacket)
    Public Event Stopped(reason As String)

    Private _handle As IntPtr = IntPtr.Zero
    Private _thread As Thread
    Private _stop As Boolean

    ''' <summary>Npcap installé ?</summary>
    Public Shared Function IsAvailable() As Boolean
        EnsureDllDir()
        Try
            Dim devs = IntPtr.Zero
            Dim err As New StringBuilder(256)
            If pcap_findalldevs(devs, err) <> 0 Then Return False
            pcap_freealldevs(devs)
            Return True
        Catch
            Return False
        End Try
    End Function

    Private Shared Sub EnsureDllDir()
        If _dllDirSet Then Return
        Dim npcapDir = Path.Combine(Environment.SystemDirectory, "Npcap")
        If Directory.Exists(npcapDir) Then
            SetDllDirectory(npcapDir)
            _dllDirSet = True ' sinon on retentera (ex. après installation de Npcap)
        End If
    End Sub

    ''' <summary>Retrouve le nom de périphérique Npcap (\Device\NPF_{GUID}) d'une interface Windows.</summary>
    Private Shared Function FindDevice(ifaceId As String) As String
        Dim devs = IntPtr.Zero
        Dim err As New StringBuilder(256)
        If pcap_findalldevs(devs, err) <> 0 Then Throw New InvalidOperationException("pcap_findalldevs : " & err.ToString())
        Try
            Dim p = devs
            While p <> IntPtr.Zero
                Dim d = Marshal.PtrToStructure(Of pcap_if)(p)
                Dim name = Marshal.PtrToStringAnsi(d.name)
                If name IsNot Nothing AndAlso name.IndexOf(ifaceId, StringComparison.OrdinalIgnoreCase) >= 0 Then Return name
                p = d.next
            End While
        Finally
            pcap_freealldevs(devs)
        End Try
        Return Nothing
    End Function

    Public Sub Start(iface As LocalInterface)
        EnsureDllDir()
        Dim dev = FindDevice(iface.Id)
        If dev Is Nothing Then Throw New InvalidOperationException($"Interface {iface.Name} introuvable dans Npcap.")
        Dim err As New StringBuilder(256)
        _handle = pcap_open_live(dev, 128, 1, 500, err)
        If _handle = IntPtr.Zero Then Throw New InvalidOperationException("pcap_open_live : " & err.ToString())
        Dim prog As New bpf_program()
        If pcap_compile(_handle, prog, "arp", 1, 0UI) = 0 Then
            pcap_setfilter(_handle, prog)
            pcap_freecode(prog)
        End If
        _stop = False
        _thread = New Thread(AddressOf Loop_) With {.IsBackground = True, .Name = "PcapArp"}
        _thread.Start()
    End Sub

    Private Sub Loop_()
        Dim reason = "arrêt demandé"
        Try
            While Not _stop
                Dim hdr As IntPtr, data As IntPtr
                Dim r = pcap_next_ex(_handle, hdr, data)
                If r = 0 Then Continue While          ' timeout
                If r < 0 Then reason = "erreur de capture" : Exit While
                Dim caplen = Marshal.ReadInt32(hdr, 8) ' pcap_pkthdr : timeval (2 x 32 bits sous Windows), caplen, len
                If caplen < 42 Then Continue While
                Dim buf(caplen - 1) As Byte
                Marshal.Copy(data, buf, 0, caplen)
                Dim pkt = Parse(buf)
                If pkt IsNot Nothing Then RaiseEvent PacketReceived(pkt)
            End While
        Catch ex As Exception
            reason = ex.Message
        End Try
        RaiseEvent Stopped(reason)
    End Sub

    Private Shared Function Parse(b As Byte()) As ArpPacket
        Dim off = 12
        Dim etype = (CInt(b(off)) << 8) Or b(off + 1)
        If etype = &H8100 Then off += 4 : etype = (CInt(b(off)) << 8) Or b(off + 1) ' VLAN
        If etype <> &H806 Then Return Nothing
        Dim a = off + 2
        If b.Length < a + 28 Then Return Nothing
        If b(a + 4) <> 6 OrElse b(a + 5) <> 4 Then Return Nothing ' hlen / plen
        Dim oper = (CInt(b(a + 6)) << 8) Or b(a + 7)
        Dim sha(5) As Byte : Array.Copy(b, a + 8, sha, 0, 6)
        Dim spa(3) As Byte : Array.Copy(b, a + 14, spa, 0, 4)
        Dim tpa(3) As Byte : Array.Copy(b, a + 24, tpa, 0, 4)
        Dim sip As New IPAddress(spa), tip As New IPAddress(tpa)
        Return New ArpPacket With {
            .SenderIp = sip,
            .SenderMac = MacToString(sha, 6),
            .TargetIp = tip,
            .IsReply = (oper = 2),
            .IsProbe = sip.Equals(IPAddress.Any),
            .IsGratuitous = sip.Equals(tip)
        }
    End Function

    Public Sub [Stop]()
        _stop = True
        _thread?.Join(1500)
        If _handle <> IntPtr.Zero Then
            pcap_close(_handle)
            _handle = IntPtr.Zero
        End If
    End Sub

    Public Sub Dispose() Implements IDisposable.Dispose
        [Stop]()
    End Sub
End Class
