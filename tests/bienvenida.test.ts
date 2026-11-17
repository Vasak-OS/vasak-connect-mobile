/**
 * La pantalla de bienvenida monta y dice el estado.
 *
 * Es la primera pantalla de la app móvil: da la bienvenida y muestra que
 * todavía no hay nada vinculado. Monta de verdad `WelcomeScreen.vue` con
 * `@vue/test-utils`, con el `EmptyState` y el `StatusDot` reales de la
 * librería (no mockeados). El `t()` de los dobles devuelve la clave, así que
 * una prueba que mira el texto mira la clave: el render tiene que contener
 * `inicio.titulo`, `inicio.descripcion` y `inicio.estado.sinVincular`.
 *
 * Si la pantalla no monta, o deja de usar la librería, o le saca alguno de
 * esos textos, esta prueba se pone en rojo.
 */

import { describe, expect, test } from 'bun:test';
import { EmptyState } from '@vasakgroup/vue-libvasak';
import { mount } from '@vue/test-utils';
import WelcomeScreen from '../src/views/WelcomeScreen.vue';

describe('la pantalla de bienvenida', () => {
	test('monta y muestra el bloque de bienvenida con el EmptyState de la librería', () => {
		const wrapper = mount(WelcomeScreen);

		expect(wrapper.exists()).toBe(true);
		expect(wrapper.findComponent(EmptyState).exists()).toBe(true);
	});

	test('dibuja el título, la descripción y el estado sin vincular', () => {
		const wrapper = mount(WelcomeScreen);
		const texto = wrapper.text();

		expect(texto).toContain('inicio.titulo');
		expect(texto).toContain('inicio.descripcion');
		expect(texto).toContain('inicio.estado.sinVincular');
	});

	test('muestra la sección de descubiertos buscando mientras no hay escritorios', () => {
		// El `invoke` del arnés no devuelve escritorios, así que la lista arranca
		// vacía: la sección tiene que mostrar su título y el texto de «buscando»,
		// no romperse ni quedar en blanco.
		const wrapper = mount(WelcomeScreen);
		const texto = wrapper.text();

		expect(texto).toContain('inicio.descubiertos.titulo');
		expect(texto).toContain('inicio.descubiertos.buscando');
	});
});
