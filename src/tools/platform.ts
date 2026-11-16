/**
 * Si la app corre en un teléfono (Android o iOS), mirado por el user agent del
 * webview.
 *
 * `App.vue` lo usa para no leer la configuración en móvil —ahí no está
 * `config-manager`—. Es una función aparte, con su argumento, para poder probar
 * el reconocimiento de cada plataforma sin montar la app ni depender del
 * `navigator` real.
 */
export function esMovil(userAgent: string = navigator.userAgent): boolean {
	return /Android|iPhone|iPad|iPod/i.test(userAgent);
}
