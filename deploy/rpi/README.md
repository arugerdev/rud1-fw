# Despliegue en Raspberry Pi

Scripts para instalar Rud1 (agente + panel web) en una Raspberry Pi real.

---

## Sistema operativo recomendado

**Raspberry Pi OS Lite (64-bit, Bookworm)** — es el mejor compromiso para una
Pi 3 con 1 GB de RAM:

- Kernel con WireGuard integrado (sin módulos externos).
- Módulos USB/IP (`usbip-core`, `usbip-host`, `vhci-hcd`) disponibles vía
  `apt install usbip`.
- `~180 MB` de RAM en reposo → queda memoria de sobra para el agente.
- Basado en Debian → apt es estable y el binario Go (CGO_ENABLED=0) corre sin
  problemas.
- Soporte oficial de la Raspberry Pi Foundation.

Alternativas viables si te hace falta: Ubuntu Server 24.04 LTS arm64 (más
pesado), DietPi (más minimalista, menos mainstream). **Evita Alpine** para
este proyecto por incompatibilidades ocasionales de CGO/musl con algunas
librerías de sistema.

---

## Preparación de la SD

1. Descarga **Raspberry Pi Imager** desde <https://www.raspberrypi.com/software/>.
2. Elige *Raspberry Pi 3* → *Raspberry Pi OS (other)* → **Raspberry Pi OS Lite
   (64-bit)**.
3. Antes de escribir, pulsa el engranaje (⚙️) y configura:

   | Campo | Valor sugerido |
   | --- | --- |
   | Set hostname | `rud1-<algo>` (ej. `rud1-taller-01`) — hará `rud1-taller-01.local` via mDNS |
   | Enable SSH | ✅ — usa clave pública si tienes una |
   | Set username and password | Usuario `pi` o el que prefieras |
   | Configure wireless LAN | SSID + pass de tu WiFi |
   | Locale settings | Tu zona horaria y teclado |

4. Escribe la imagen, mete la SD en la Pi, arranca.

5. Desde tu máquina, comprueba acceso SSH:

   ```bash
   ssh pi@rud1-taller-01.local
   # (acepta la huella RSA la primera vez)
   ```

Si `*.local` no resuelve desde Windows, instala **Bonjour Print Services** de
Apple o usa la IP directa (mira tu router).

---

## Flujo de instalación

Todo está automatizado con dos scripts:

- **`build-release.sh`** — lo ejecutas **en tu máquina de desarrollo**.
  Cross-compila el agente Go para `linux/arm64`, construye el panel Astro y
  empaqueta todo en un `tar.gz`.
- **`install.sh`** — lo ejecutas **dentro de la Pi**. Instala dependencias
  APT, módulos de kernel, systemd unit, nginx + estáticos, config y arranca
  los servicios.

### 1) Generar el release (máquina de desarrollo)

Requisitos: `go 1.23+`, `node 20+` y `npm`.

Layout asumido:

```
<tu-carpeta>/
  rud1-fw/      ← este repo
  rud1-app/     ← panel Astro (hermano)
```

Desde `rud1-fw/`:

```bash
./deploy/rpi/build-release.sh
# → produce deploy/rpi/dist/rud1-release-<version>-linux-arm64.tar.gz
```

Opciones:

```bash
# 32-bit (si insistes en RPi OS 32-bit):
GOARCH=arm ./deploy/rpi/build-release.sh

# Sin UI web (solo agente):
RUD1_APP_DIR= ./deploy/rpi/build-release.sh
```

### 2) Copiar + instalar en la Pi

```bash
TARBALL=$(ls -t deploy/rpi/dist/rud1-release-*.tar.gz | head -1)
PI=pi@rud1-taller-01.local

# Copia
scp "$TARBALL" "$PI:/tmp/"

# Desempaqueta e instala
ssh "$PI" bash -s <<EOF
  set -e
  sudo rm -rf /tmp/rud1-release
  mkdir -p /tmp/rud1-release
  tar -C /tmp/rud1-release -xzf /tmp/$(basename "$TARBALL")
  sudo RUD1_API_SECRET='<el-secreto-del-backend>' /tmp/rud1-release/install.sh
EOF
```

`RUD1_API_SECRET` es el valor de la variable de entorno `DEVICE_API_SECRET`
del rud1-es (Vercel → Settings → Environment Variables). Si lo omites, el
script lo pedirá por stdin.

Al terminar imprime:

```
  Registration code:  RUD1-XXXXXXXX-XXXXXXXX
  Pair at: https://rud1.es/dashboard/devices?pair=RUD1-XXXXXXXX-XXXXXXXX
```

Abre esa URL (o escanea el QR desde `http://rud1-taller-01.local`) y empareja
el dispositivo con tu workspace.

---

## Variables de entorno del installer

Todas opcionales — el script tiene defaults sensatos.

| Variable | Default | Descripción |
| --- | --- | --- |
| `RUD1_API_SECRET` | *(prompt)* | Secreto compartido con rud1-es. Se escribe en `/etc/rud1-agent/config.yaml`. |
| `RUD1_HOSTNAME` | *(se mantiene)* | Fuerza un hostname nuevo (actualiza `/etc/hosts`). |
| `RUD1_CLOUD_URL` | `https://rud1.es` | URL del backend de nube. |
| `RUD1_SKIP_APT` | `0` | `1` para saltar `apt update/install` en reinstalaciones. |
| `RUD1_ENABLE_USBIP` | `1` | `0` para no instalar `usbip` ni cargar sus módulos. |
| `RUD1_DISABLE_NGINX` | `0` | `1` si prefieres servir el panel desde otro sitio. |

---

## Qué hace exactamente `install.sh`

1. Actualiza APT e instala: `wireguard`, `wireguard-tools`, `usbip`, `hwdata`,
   `nginx-light`, `avahi-daemon` (mDNS), `chrony` (NTP).
2. Configura el hostname (opcional).
3. Carga los módulos de kernel `usbip-core`, `vhci-hcd`, `usbip-host` y los
   registra en `/etc/modules-load.d/rud1.conf`.
4. Aplica sysctl (`ip_forward=1`, conntrack) desde
   `/etc/sysctl.d/99-rud1.conf`.
5. Copia el binario a `/usr/local/bin/rud1-agent`.
6. Crea `/etc/rud1-agent/config.yaml` (si no existe) y escribe el
   `api_secret`.
7. Instala y habilita la unit systemd `rud1-agent.service`.
8. Publica el panel Astro en `/var/www/rud1` y lo expone en nginx (`:80`).
9. Arranca el agente, espera a que genere la identidad y muestra el
   `registration_code`.

El binario es **idempotente**: re-ejecutar el script actualiza el agente y el
panel sin tocar `config.yaml` ni la identidad del dispositivo.

---

## Acceso al dispositivo tras instalar

| Recurso | URL |
| --- | --- |
| Panel web | `http://<hostname>.local` |
| API del agente | `http://<hostname>.local:7070` |
| Logs en vivo | `ssh <user>@<hostname>.local 'journalctl -u rud1-agent -f'` |
| Reinicio del agente | `sudo systemctl restart rud1-agent` |
| Config | `sudo nano /etc/rud1-agent/config.yaml` |

---

## Actualizar un dispositivo ya instalado

Re-genera el release en tu máquina, cópialo a la Pi y vuelve a lanzar
`install.sh` — mantiene el config y la identidad:

```bash
./deploy/rpi/build-release.sh
scp deploy/rpi/dist/rud1-release-*.tar.gz pi@rud1-taller-01.local:/tmp/
ssh pi@rud1-taller-01.local \
  'sudo tar -C /tmp/rud1-release -xzf /tmp/rud1-release-*.tar.gz && \
   sudo RUD1_SKIP_APT=1 /tmp/rud1-release/install.sh'
```

---

## Desinstalar

```bash
ssh pi@rud1-taller-01.local 'sudo /tmp/rud1-release/uninstall.sh'
```

Por defecto conserva `/etc/rud1-agent` y `/var/lib/rud1-agent` para poder
reinstalar con la misma identidad. Para borrarlo todo:

```bash
ssh pi@rud1-taller-01.local 'sudo RUD1_PURGE=1 /tmp/rud1-release/uninstall.sh'
```

---

## Troubleshooting rápido

| Síntoma | Qué mirar |
| --- | --- |
| `rud1-agent` en estado `failed` | `journalctl -u rud1-agent -n 200` |
| `apt` no encuentra `usbip` | Asegúrate de estar en Bookworm (`cat /etc/os-release`). |
| El panel no carga en `:80` | `sudo nginx -t` y `systemctl status nginx`. |
| `rud1.local` no resuelve | Comprueba que `avahi-daemon` está activo; en Windows instala Bonjour. |
| Heartbeat 401 | `api_secret` no coincide con `DEVICE_API_SECRET` del backend. |
| Heartbeat 400 | Versión antigua del backend: actualiza rud1-es a `>= e24d9e8`. |

---

## Roadmap del instalador

- [ ] Imagen SD preconfigurada (first-boot script que auto-ejecuta
      `install.sh`) — evitaría tener que hacer scp + ssh.
- [ ] Firma GPG del tarball y verificación en `install.sh`.
- [ ] Canal OTA (el backend ya expone `/api/v1/devices/firmware/pending`).
- [ ] Helper con capabilities privilegiadas separado del agente para poder
      dropear a `DynamicUser=yes` en la unit.
