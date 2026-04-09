# CPC Alarm Center Pro

Versión enfocada solo en **conexión directa CPC/E2**.

## Qué cambió

- eliminada la entrada por correo
- eliminados los ajustes IMAP/SMTP
- login con **usuario y contraseña**
- varias CPC/E2 al mismo tiempo
- panel de estado por cada CPC
- notificaciones del navegador cuando la app está abierta
- soporte para **web push** en segundo plano si publicas la app con HTTPS y configuras llaves VAPID
- lista para uso local o remoto

## Límite de CPCs

No hay un límite fijo programado en el código. En la práctica, la cantidad real depende de la PC o servidor, la red y el volumen de eventos.

## Ejecutarla en Windows

```bat
cd %USERPROFILE%\Downloads\cpc_alarm_app_multi\cpc_alarm_app
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Luego abre:

```text
http://127.0.0.1:5000
```

La primera vez te pedirá crear el usuario administrador.

## Uso local

La app arranca en `0.0.0.0`, así que puedes abrirla desde otra máquina o teléfono en la misma red con:

```text
http://IP-DE-TU-PC:5000
```

## Uso remoto

Tienes 3 formas recomendadas:

1. **ZeroTier/Tailscale** para entrar seguro sin abrir puertos.
2. Publicarla con **HTTPS** en Render, Railway o un VPS.
3. Port forwarding solo si sabes lo que haces y tu ISP no usa CG-NAT.

## Notificaciones

### Con la app abierta
Funciona en PC y teléfono con el botón **Activar notificaciones**.

### En segundo plano
Para recibir notificaciones con la app cerrada o instalada como PWA necesitas:

- HTTPS
- navegador compatible
- llaves VAPID configuradas en variables de entorno

## Variables importantes

- `SECRET_KEY`
- `PUBLIC_BASE_URL`
- `VAPID_PUBLIC_KEY`
- `VAPID_PRIVATE_KEY`
- `VAPID_CLAIMS_EMAIL`

## Conectar CPCs

En **Ajustes** agrega una o varias CPCs con:

- nombre
- IP o hostname
- puerto (normalmente `14106`)
- timeout
- modo de buffer

## Nota honesta

La app ya puede mantener múltiples conexiones TCP a CPC/E2. La interpretación exacta de todas las tramas depende del formato real que mande cada equipo. Por eso también guarda eventos brutos para ajustar el parser si hace falta.


## SMS por usuario

Cada usuario puede guardar su propio número en **My account** y activar o desactivar SMS.

Variables nuevas para SMS con Twilio:

- `TWILIO_ACCOUNT_SID`
- `TWILIO_AUTH_TOKEN`
- `TWILIO_FROM_NUMBER`

Formato recomendado del teléfono: `+13055550123`

Cuando entra una alarma nueva, la app envía:

- notificación web
- SMS al usuario dueño de esa CPC, si tiene SMS activado

## Icono

Se incluyó el icono personalizado de CPC ALERT como icono de la PWA y para iPhone.
