/**
 * Los tres manifiestos cuentan la misma identidad.
 *
 * El rebrand desde la plantilla `vapp` tiene que tocar los tres a la vez:
 * `package.json`, `src-tauri/Cargo.toml` y `src-tauri/tauri.conf.json`. Si uno
 * se queda con el nombre, la versión o el identifier de la plantilla, el CI de
 * versión no lo nota (mira que coincidan entre sí, no contra qué app son) y la
 * app se publica con media identidad vieja.
 *
 * El `Cargo.toml` se lee como texto a propósito: no hay parser de TOML a mano y
 * los dos campos que importan —`[package] name` y `[lib] name`— se encuentran
 * con una expresión por sección, sin traer una dependencia para esto.
 */

import { fileURLToPath } from 'node:url';
import { describe, expect, test } from 'bun:test';

// `fileURLToPath` y no `.pathname`: un checkout con un espacio en la ruta
// (`/tmp/mobile app/`) deja `.pathname` con `%20` y las lecturas de manifiesto
// buscan un archivo que no existe.
const RAIZ = fileURLToPath(new URL('..', import.meta.url));

const paquete = await Bun.file(`${RAIZ}package.json`).json();
const tauri = await Bun.file(`${RAIZ}src-tauri/tauri.conf.json`).json();
const cargoTexto = await Bun.file(`${RAIZ}src-tauri/Cargo.toml`).text();

/** El valor de `name`/`version` de una sección del `Cargo.toml` leído como texto. */
function campoDeSeccion(texto: string, seccion: string, campo: string): string | undefined {
	const re = new RegExp(`\\[${seccion}\\][\\s\\S]*?\\b${campo}\\s*=\\s*"([^"]+)"`);
	return texto.match(re)?.[1];
}

describe('la identidad de los manifiestos', () => {
	test('las tres versiones coinciden y valen 0.1.0', () => {
		const versionCargo = campoDeSeccion(cargoTexto, 'package', 'version');

		expect(paquete.version).toBe('0.1.0');
		expect(versionCargo).toBe('0.1.0');
		expect(tauri.version).toBe('0.1.0');
	});

	test('el package.json se llama vasak-connect-mobile', () => {
		expect(paquete.name).toBe('vasak-connect-mobile');
	});

	test('el Cargo.toml nombra el paquete y la librería del móvil', () => {
		expect(campoDeSeccion(cargoTexto, 'package', 'name')).toBe('vasak-connect-mobile');
		expect(campoDeSeccion(cargoTexto, 'lib', 'name')).toBe('vasak_connect_mobile_lib');
	});

	test('el tauri.conf.json tiene el identifier del móvil y un productName', () => {
		expect(tauri.identifier).toBe('ar.net.vasak.os.ConnectMobile');
		expect(tauri.productName).toBeTruthy();
	});

	test('no queda el nombre viejo vapp en ningún manifiesto', () => {
		expect(JSON.stringify(paquete)).not.toContain('vapp');
		expect(JSON.stringify(tauri)).not.toContain('vapp');
		expect(cargoTexto).not.toContain('vapp');
	});
});
