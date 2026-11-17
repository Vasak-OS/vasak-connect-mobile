/**
 * `esMovil` distingue el teléfono del escritorio por el user agent.
 *
 * Se le pasa el user agent como argumento —el que la función acepta justo para
 * esto— y así cada plataforma se prueba sin tocar el `navigator` global ni
 * montar la app. El caso sin argumento confirma que, por omisión, mira el
 * `navigator` real (acá, el de happy-dom).
 */

import { describe, expect, test } from 'bun:test';
import { esMovil } from '../src/tools/platform';

// El user agent de un WebKitGTK de escritorio: ningún token de móvil.
const ESCRITORIO =
	'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/8.0 Safari/605.1.15';

describe('esMovil', () => {
	test('un user agent de escritorio no es móvil', () => {
		expect(esMovil(ESCRITORIO)).toBe(false);
	});

	test('reconoce Android', () => {
		expect(
			esMovil(
				'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
			),
		).toBe(true);
	});

	test('reconoce iPhone', () => {
		expect(
			esMovil(
				'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
			),
		).toBe(true);
	});

	test('reconoce iPad', () => {
		expect(
			esMovil(
				'Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
			),
		).toBe(true);
	});

	test('reconoce iPod', () => {
		expect(
			esMovil(
				'Mozilla/5.0 (iPod touch; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1',
			),
		).toBe(true);
	});

	test('sin argumento lee el navigator', () => {
		// happy-dom da un user agent de escritorio, así que por omisión da false.
		expect(esMovil()).toBe(esMovil(navigator.userAgent));
		expect(esMovil()).toBe(false);
	});
});
