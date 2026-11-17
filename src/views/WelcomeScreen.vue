<script lang="ts" setup>
/**
 * La primera pantalla de Vasak Connect.
 *
 * Es la base: da la bienvenida y dice el estado —todavía sin vincular—, sin
 * nada de la lógica de canal ni de pareo, que llega en otro PR. Todo lo que
 * dibuja sale de `@vasakgroup/vue-libvasak` y de los tokens del sistema: el
 * `EmptyState` para el bloque de bienvenida, el `StatusDot` para el estado, y
 * los colores, radios y sombras del esquema de VasakOS (decisión 8 del taller).
 *
 * No hay marco de ventana: en un teléfono la ventana la gobierna el sistema, no
 * la aplicación.
 */
import { useI18n } from '@vasakgroup/tauri-plugin-i18n';
import { EmptyState, StatusDot } from '@vasakgroup/vue-libvasak';

const { t } = useI18n();
</script>

<template>
  <main class="flex min-h-dvh flex-col items-center justify-center gap-6 bg-ui-bg p-6">
    <section
      class="flex w-full max-w-sm flex-col items-center gap-5 rounded-corner-l bg-ui-surface/70 p-6 shadow-surface-l">
      <EmptyState
        :title="t('inicio.titulo')"
        :note="t('inicio.descripcion')"
        icon="network-wireless"
        icon-type="symbol" />

      <div class="flex items-center gap-2">
        <StatusDot tone="neutral" :label="t('inicio.estado.sinVincular')" />
        <span class="text-tx-muted">{{ t('inicio.estado.sinVincular') }}</span>
      </div>
    </section>
  </main>
</template>
