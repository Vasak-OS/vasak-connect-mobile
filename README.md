# vasak-connect-mobile — el compañero móvil de VasakOS

Aplicación móvil (Android / iOS) hecha con **Tauri 2 Mobile + Vue 3 +
TypeScript + Tailwind 4**, con el mismo design system que el escritorio
(`@vasakgroup/vue-libvasak`, config-manager, vicons, i18n). Un solo codebase para
las dos plataformas.

Nace de la plantilla `vapp` del escritorio, pero sin su ventana: en un teléfono
la ventana la gobierna el sistema. Lo que quedó es la base del design system y el
contrato de red; la lógica de **canal y pareo** (SAS/RFC-6189, protocolo v2) llega
en PRs siguientes.

---

## Estado de esta base

- Primera pantalla de bienvenida/estado con los componentes y tokens del sistema.
- Dependencia del contrato de red (`vasak-connect-protocol`) declarada; **sin**
  cliente de canal todavía.
- Andamio de Android: ver abajo. **iOS no se inicializa en Linux.**

## Compilar

Dependencias del frontend y pruebas corren en cualquier plataforma:

```bash
bun install
bun test                                          # frontend
cargo test --manifest-path src-tauri/Cargo.toml   # backend (host)
```

### Android

Necesita el SDK + NDK de Android y los targets de Rust. En CachyOS / Arch:

```bash
sudo pacman -S jdk-openjdk
paru -S android-sdk-cmdline-tools-latest          # o instalar Android Studio
export ANDROID_HOME=/opt/android-sdk
export NDK_HOME="$ANDROID_HOME/ndk/<versión>"
sdkmanager "platform-tools" "platforms;android-34" "build-tools;34.0.0" "ndk;27.1.12297006"

rustup target add aarch64-linux-android armv7-linux-androideabi i686-linux-android x86_64-linux-android

bunx tauri android init                           # genera src-tauri/gen/android
bunx tauri android dev                            # emulador o dispositivo
bunx tauri android build                          # .apk / .aab
```

`tauri android init` genera el proyecto Gradle en `src-tauri/gen/android/`, que no
se versiona (lo regenera el init). Hay que correrlo una vez por checkout.

### iOS

`tauri ios init` **sólo corre en macOS con Xcode** — no se puede desde Linux. En
un Mac: `bunx tauri ios init && bunx tauri ios dev`. El codebase es portable; lo
único que falta es inicializar el proyecto Xcode allá.

---

## El design system (decisión 8 del taller)

La forma es de Once UI; el color es de VasakOS. Todo sale de
`@vasakgroup/vue-libvasak` y de sus tokens, nunca de colores literales ni de la
paleta de Tailwind.

### Componentes

Los botones, campos, tarjetas, estados vacíos, indicadores y diálogos salen de
`@vasakgroup/vue-libvasak`; la aplicación no dibuja los suyos. Si falta uno, se
suma **a la librería** (vue-libvasak#74). La pantalla de bienvenida usa
`EmptyState` y `StatusDot`.

### Colores, radios y forma

De `@vasakgroup/vue-libvasak/tokens.css`, que `main.css` importa después de
Tailwind: los radios `rounded-corner-*` (derivados del radio que eligió la
persona), los bordes `ui-line`, los velos de estado, las sombras `shadow-surface-*`
y las curvas `ease-ui`. Los colores salen sólo del esquema (`bg-ui-surface/70`,
`text-tx-main`), que pisa `tauri-plugin-config-manager`; ni hexadecimales, ni
`rgb()`, ni la paleta de Tailwind. `tests/design-guard.test.ts` lo hace cumplir.

Lo que cambia con el ancho va con consultas de contenedor (`@container`, `@sm:`)
o un `ResizeObserver`, **nunca** con `sm:`/`md:` ni `matchMedia`.

### Iconos

`ThemeIcon` de `@vasakgroup/vue-libvasak`, siempre por **nombre** y nunca por
ruta: el pack de iconos cambia en caliente y sus rutas no son estables.

```vue
<ThemeIcon name="network-wireless" :size="24" :alt="t('app.nombre')" />
<ThemeIcon name="view-refresh" type="symbol" :size="16" />
```

`type` elige la variante: `icon` la común en color y `symbol` la monocroma de los
botones de acción.

---

## Textos traducidos

Todo texto que ve una persona va en `src-tauri/locales/{es,en}.yml`. Nunca una
cadena literal en un `.vue`. El `t()` del plugin toma un solo argumento y no
interpola: el marcador es `{0}` y se reemplaza con `src/tools/interpolar.ts`
(nunca `String.replace` a mano — interpreta `$&`, `$'` y compañía).

Dos reglas de los `.yml`, las dos con test: si el valor contiene `: ` va entre
comillas, y los dos idiomas tienen las mismas claves y los mismos marcadores.

## Política de contenido

`tauri.conf.json` trae una CSP con `script-src 'self'`. Cuando el cliente de
canal necesite hablar con el escritorio, se agrega ese origen a `connect-src`
**ahí**, sin aflojar la política entera. `main.ts` registra un reportador de
violaciones (saneando las URLs antes de escribirlas).

## Tests

**Cada cambio va con tests, en el mismo commit**, y la prueba tiene que fallar
sin el cambio. Lo que conviene probar es lo que se rompe callado: parsers,
recortes de texto, límites, marcadores de interpolación.

- `tests/design-guard.test.ts` — colores del esquema, radios del sistema, iconos
  del tema, sin puntos de corte de la pantalla, la forma de Once UI.
- `tests/identidad.test.ts` — los manifiestos dicen la misma versión y la misma
  identidad móvil.
- `tests/bienvenida.test.ts` — la primera pantalla monta.
- `src-tauri/tests/locales.rs` — que los catálogos parseen y coincidan.

## Estructura

```
src/
  App.vue                 tema y configuración; monta la pantalla
  main.ts                 plugins, CSP, i18n
  assets/main.css         Tailwind, tokens.css de la librería y el piso del esquema
  views/WelcomeScreen.vue la primera pantalla
  tools/interpolar.ts     interpolación y plurales de textos traducidos
  tools/theme-cache.ts    recuerda el tema aplicado
tests/                    tests del frontend (bun test)
src-tauri/
  src/lib.rs              registro de plugins
  src/locales.rs          resolución de idioma y de la ruta de catálogos
  locales/{es,en}.yml     los textos
  tauri.conf.json         identidad móvil, CSP
```

## Licencia

GPL-3.0-or-later.
