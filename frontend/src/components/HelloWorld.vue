<template>
	<div class="hello">
		<h1>{{ msg }}</h1>
	</div>
</template>

<script setup lang="ts">
import {defineProps} from "vue";

defineProps<{
	msg: string
}>();

</script>
