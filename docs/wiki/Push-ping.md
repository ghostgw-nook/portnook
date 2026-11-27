# Push ping (preview)

> **Applies to:** portnook 0.40 (push) · [Versions](Versions)

> Preview only: image tag `ghcr.io/ghostgw-nook/portnook:push`, pre-releases `v0.40.0-push.N`. `latest` does not
> have it yet. The matching app is not released yet.

Apps can get the current address of the media server (`https://<sub>.<name>.myaddr.tools:<port>`) without asking
the redirect host each time. portnook keeps one **encrypted, signed file per device** on any WebDAV storage you
choose and nudges Android devices by push after a change. The storage only ever sees encrypted bytes.

## How it works

1. **Sign in once.** In the app, enter the entry address (your redirect host) and sign in to the media server as
   usual (password or Quick Connect). The app follows the 302 to the VPN port, your proxy passes `/_pn/` to
   portnook, and portnook checks the app's media server token against the media server (`/Users/Me`). Only the
   user id is kept, never the token.
2. **Device file.** portnook gives the device a random file name and writes `<random>.bin` to the storage,
   sealed for the device's own key and signed with portnook's key.
3. **After a change** of exit IP or port (and every 6 hours) portnook rewrites the files. Android devices then get
   an empty Firebase message ("fetch again"); the message carries no address.
4. **On every app start** the app fetches its file and checks the signature.

Uploads and Firebase requests go through the VPN tunnel only, never through the home line. Removed devices get
their file deleted.

## 1. Reverse proxy: path `/_pn/`

The device API listens on its own port (default **8099**) and answers only `/_pn/hello`, `/_pn/register` and
`/_pn/device`. The portnook web UI stays internal. Add the path to the **media server's proxy host**, the one the
redirect points to.

**Nginx Proxy Manager:** proxy host of the media server → **Custom locations** → **Add location**:

- Location: `/_pn/`
- Scheme `http`, forward hostname `<portnook LAN IP>`, port `8099`.

**Zoraxy:** HTTP proxy rule of the media server → **Virtual directories** → add `/_pn/` with target
`<portnook LAN IP>:8099`, TLS to target off.

The API accepts the path with or without the `/_pn` prefix, so it does not matter whether the proxy keeps it.

Check: `https://<sub>.<name>.myaddr.tools:<port>/_pn/hello` answers `{"ok": true, "service": "portnook push"}`.

## 2. Storage (WebDAV)

Any WebDAV folder with https works (a web host, Nextcloud, a storage box). portnook needs `PUT` and `DELETE`.
The apps need to read the files over https; give the fetch address if it differs from the upload address (e.g.
a public web folder on the same host).

## 3. Settings in portnook

Page **Redirect** → **Push ping for apps**:

- **Turn on push ping**, **Device API port** (8099),
- **Media server on the LAN**, e.g. `http://192.168.1.30:8096` (for the login check),
- **WebDAV folder**, **User**, **Password** (write-only), **Fetch address** (optional),
- **Save**. The card **Status** shows the device API, the last upload and Firebase.

## 4. Firebase (Android push)

In the Firebase console: create a project, add the Android app, then **Project settings** → **Service accounts**
→ **Generate new private key**. Paste the JSON into **Service account (JSON)** and save. The key is stored
write-only (`/data/push/fcm-key.pem`, mode 600) and never shown again.

Without a service account everything works, but Android devices only see a new address at the next app start.
iOS and tvOS follow later.

## Devices

The table lists each device with name, media server user, platform, whether it has a push token and when its
file was last published. **Delete** removes the device and its file; the app has to sign in again.

## Limits

- The 302 shows name and port to anyone who calls the entry address; push ping only spares the apps from asking
  it. See [Redirect host](Redirect-host).
- Sign-ins arrive from portnook's LAN IP unless the proxy passes the real visitor IP
  ([PROXY protocol](PROXY-protocol)); failed sign-ins are rate limited per address.
- The certificate is the normal Let's Encrypt certificate of the name; a pinned self-signed certificate is planned.
