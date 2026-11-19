Imports System.Net
Imports System.Runtime.InteropServices
Imports System.Security.Principal

''' <summary>Appels Win32 iphlpapi : ARP, cache ARP, purge.</summary>
Public Module NetNative

    <StructLayout(LayoutKind.Sequential)>
    Public Structure MIB_IPNETROW
        Public dwIndex As Integer
        Public dwPhysAddrLen As Integer
        <MarshalAs(UnmanagedType.ByValArray, SizeConst:=8)>
        Public bPhysAddr As Byte()
        Public dwAddr As UInteger
        Public dwType As Integer
    End Structure

    Public Const MIB_IPNET_TYPE_INVALID As Integer = 2
    Public Const MIB_IPNET_TYPE_DYNAMIC As Integer = 3
    Public Const MIB_IPNET_TYPE_STATIC As Integer = 4

    Private Const ERROR_INSUFFICIENT_BUFFER As Integer = 122
    Private Const NO_ERROR As Integer = 0

    <DllImport("iphlpapi.dll", ExactSpelling:=True)>
    Private Function SendARP(destIP As UInteger, srcIP As UInteger, pMacAddr As Byte(), ByRef phyAddrLen As UInteger) As Integer
    End Function

    <DllImport("iphlpapi.dll", ExactSpelling:=True)>
    Private Function GetIpNetTable(pIpNetTable As IntPtr, ByRef pdwSize As Integer, bOrder As Boolean) As Integer
    End Function

    <DllImport("iphlpapi.dll", ExactSpelling:=True)>
    Private Function DeleteIpNetEntry(ByRef pArpEntry As MIB_IPNETROW) As Integer
    End Function

    ''' <summary>IPv4 -> UInteger ordre réseau (attendu par iphlpapi).</summary>
    Public Function ToNetUInt(ip As IPAddress) As UInteger
        Return BitConverter.ToUInt32(ip.GetAddressBytes(), 0)
    End Function

    Public Function FromNetUInt(v As UInteger) As IPAddress
        Return New IPAddress(BitConverter.GetBytes(v))
    End Function

    ''' <summary>IPv4 -> UInteger ordre hôte (pour calcul de plages / tri).</summary>
    Public Function ToHostUInt(ip As IPAddress) As UInteger
        Dim b = ip.GetAddressBytes()
        Return (CUInt(b(0)) << 24) Or (CUInt(b(1)) << 16) Or (CUInt(b(2)) << 8) Or CUInt(b(3))
    End Function

    Public Function FromHostUInt(v As UInteger) As IPAddress
        Return New IPAddress(New Byte() {CByte((v >> 24) And &HFFUI), CByte((v >> 16) And &HFFUI), CByte((v >> 8) And &HFFUI), CByte(v And &HFFUI)})
    End Function

    Public Function MacToString(mac As Byte(), len As Integer) As String
        If mac Is Nothing OrElse len <= 0 Then Return ""
        Dim parts(len - 1) As String
        For i = 0 To len - 1
            parts(i) = mac(i).ToString("X2")
        Next
        Return String.Join(":", parts)
    End Function

    ''' <summary>Requête ARP active. Renvoie la MAC ou "" si pas de réponse.</summary>
    Public Function ArpResolve(dest As IPAddress, src As IPAddress) As String
        Dim mac(5) As Byte
        Dim len As UInteger = 6
        Dim srcVal As UInteger = If(src Is Nothing, 0UI, ToNetUInt(src))
        Dim r = SendARP(ToNetUInt(dest), srcVal, mac, len)
        If r <> NO_ERROR OrElse len = 0 Then Return ""
        Dim s = MacToString(mac, CInt(len))
        If s = "00:00:00:00:00:00" Then Return ""
        Return s
    End Function

    ''' <summary>Supprime l'entrée du cache ARP pour forcer une nouvelle requête (admin requis).</summary>
    Public Function ArpDeleteEntry(ifIndex As Integer, ip As IPAddress) As Boolean
        Dim row As New MIB_IPNETROW With {
            .dwIndex = ifIndex,
            .dwPhysAddrLen = 0,
            .bPhysAddr = New Byte(7) {},
            .dwAddr = ToNetUInt(ip),
            .dwType = 0
        }
        Return DeleteIpNetEntry(row) = NO_ERROR
    End Function

    ''' <summary>Lit la table ARP Windows (optionnellement filtrée sur une interface).</summary>
    Public Function ReadArpTable(Optional ifIndex As Integer = -1) As List(Of ArpEntry)
        Dim result As New List(Of ArpEntry)
        Dim size As Integer = 0
        Dim r = GetIpNetTable(IntPtr.Zero, size, True)
        If r <> ERROR_INSUFFICIENT_BUFFER OrElse size = 0 Then Return result
        Dim buf = Marshal.AllocHGlobal(size)
        Try
            r = GetIpNetTable(buf, size, True)
            If r <> NO_ERROR Then Return result
            Dim count = Marshal.ReadInt32(buf)
            Dim rowSize = Marshal.SizeOf(GetType(MIB_IPNETROW))
            Dim ptr = IntPtr.Add(buf, 4)
            For i = 0 To count - 1
                Dim row = Marshal.PtrToStructure(Of MIB_IPNETROW)(ptr)
                ptr = IntPtr.Add(ptr, rowSize)
                If ifIndex >= 0 AndAlso row.dwIndex <> ifIndex Then Continue For
                If row.dwType = MIB_IPNET_TYPE_INVALID Then Continue For
                Dim mac = MacToString(row.bPhysAddr, Math.Min(row.dwPhysAddrLen, 8))
                If mac = "" OrElse mac = "00:00:00:00:00:00" OrElse mac = "FF:FF:FF:FF:FF:FF" Then Continue For
                Dim ip = FromNetUInt(row.dwAddr)
                Dim b0 = ip.GetAddressBytes()(0)
                If b0 >= 224 Then Continue For ' multicast / broadcast
                result.Add(New ArpEntry With {
                    .Ip = ip,
                    .Mac = mac,
                    .IfIndex = row.dwIndex,
                    .IsStatic = (row.dwType = MIB_IPNET_TYPE_STATIC)
                })
            Next
        Finally
            Marshal.FreeHGlobal(buf)
        End Try
        Return result
    End Function

    ''' <summary>MAC actuellement dans le cache ARP Windows pour une IP (= dernière réponse reçue), ou "".</summary>
    Public Function ReadArpEntry(ifIndex As Integer, ip As IPAddress) As String
        For Each e In ReadArpTable(ifIndex)
            If e.Ip.Equals(ip) Then Return e.Mac
        Next
        Return ""
    End Function

    Public Function IsAdmin() As Boolean
        Using id = WindowsIdentity.GetCurrent()
            Return New WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator)
        End Using
    End Function

End Module

Public Class ArpEntry
    Public Property Ip As IPAddress
    Public Property Mac As String
    Public Property IfIndex As Integer
    Public Property IsStatic As Boolean
End Class
