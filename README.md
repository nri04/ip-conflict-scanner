# IP Conflict Scanner (VB.NET / WinForms / .NET 8)

Scan d'un réseau local IPv4 : IP, MAC, fabricant, nom d'hôte, ping — avec détection des conflits d'IP.

https://github.com/](https://github.com/)nri04/ip-conflict-scanner/releases/latest/download/IpConflictScanner.zip


## Compilation

```
dotnet build -c Release
```
ou ouvrir `IpConflictScanner.vbproj` dans Visual Studio 2022. Windows uniquement (iphlpapi.dll).
Exe autonome : `dotnet publish -c Release -r win-x64 --self-contained -p:PublishSingleFile=true`

L'exe demande l'élévation admin (manifest) : nécessaire pour purger le cache ARP entre deux passes.

Optionnel : déposer `oui.csv` (https://standards-oui.ieee.org/oui/oui.csv) à côté de l'exe pour la base fabricants complète.

## Détection des conflits

| Méthode | Ce qui est détecté |
|---|---|
| ARP multi-passes (purge cache + SendARP, N passes décalées) | 2+ MAC différentes répondent pour la même IP → **CONFLIT IP** |
| Sonde double à chaque requête : 1ère réponse (SendARP) vs dernière (cache Windows après 250 ms) | 2 machines répondent à la même requête → **CONFLIT IP**, note « 2 répondeurs : 1ère=X / dernière=Y » |
| Table ARP Windows | hôtes qui bloquent le ping, entrées statiques |
| État DAD Windows de l'interface | votre propre IP utilisée par une autre machine → **CONFLIT IP AVEC CE PC** |
| Surveillance continue (table ARP + re-sondage actif) | MAC qui change pour une IP → **MAC CHANGÉE** (alerte renforcée si passerelle : usurpation ARP possible) |
| Analyse croisée | même MAC sur plusieurs IP → **MAC multi-IP** (routeur/proxy ARP, VM, alias, ou spoofing) |

Couleurs : rouge = conflit, orange = MAC multi-IP, bleu = ce PC, vert = passerelle.
Clic droit → « Re-tester cette IP (20 passes ARP) » pour confirmer un conflit intermittent.

## Limites

- SendARP renvoie la première réponse reçue : un conflit est vu quand les deux machines gagnent chacune au moins une passe. Augmenter le nombre de passes (10–20) ou laisser tourner la surveillance pour les conflits intermittents.
- Uniquement le segment L2 local (l'ARP ne traverse pas les routeurs).
- Sans droits admin, le cache ARP n'est pas purgé : les passes suivantes renvoient la MAC en cache, la détection est très dégradée.

## Ajouts v1.1

- **Appareil double interface** : si la même paire de MAC est en conflit sur plusieurs IP, la ligne indique « 1 appareil filaire + Wi-Fi probable » (ex. caméra branchée en Ethernet avec le Wi-Fi resté actif). Solution : couper l'une des deux interfaces.
- **Hors sous-réseau** : tout appareil vu en ARP avec une IP hors du sous-réseau de l'interface est signalé (orange), comme le fait la Bbox.
- **Écoute passive ARP (Npcap)** : case à cocher, active si Npcap est installé (https://npcap.com, installé aussi par Wireshark). Capture toutes les trames ARP : voit chaque réponse (pas seulement la 1ère/dernière) et les appareils mal configurés dans un autre sous-réseau, invisibles autrement pour Windows.
- **Base fabricants** : oui.csv téléchargé automatiquement au premier lancement (puis mis à jour s'il a plus de 6 mois), à côté de l'exe ou dans %LOCALAPPDATA%\IpConflictScanner.
- Passes ARP par défaut : 3 (les sondes sont séquentielles pour éviter les faux conflits).

## Ajouts v1.2

- **IP réattribuée ≠ conflit** : chaque IP garde l'historique chronologique de ses MAC. Un conflit n'est signalé que si deux MAC répondent à la même requête, ou si une MAC revient après une autre en moins de 10 min (A → B → A). Une MAC remplacée par une autre sans retour (bail DHCP, téléphone à MAC aléatoire qui a changé d'IP) donne « IP réattribuée » (ligne normale), avec en note « avant : MAC → nouvelle IP ».
- **Analyse recalculée** : « MAC multi-IP », « double interface » et leurs notes sont recalculés à chaque analyse (plus d'alerte qui reste après correction) ; une MAC partie sur une autre IP ne compte plus comme MAC multi-IP.
- Surveillance : re-sondage séquentiel (les sondes ARP étaient déjà sérialisées), alerte sonore seulement sur conflit réel ou changement de MAC de la passerelle.
