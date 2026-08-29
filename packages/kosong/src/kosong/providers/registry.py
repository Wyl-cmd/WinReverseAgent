from __future__ import annotations

from kosong.providers.descriptors import ModelDescriptor, ProviderDescriptor
from kosong.providers.descriptors.anthropic import ANTHROPIC_DESCRIPTOR
from kosong.providers.descriptors.deepseek import DEEPSEEK_DESCRIPTOR
from kosong.providers.descriptors.google import GOOGLE_DESCRIPTOR
from kosong.providers.descriptors.ollama import OLLAMA_DESCRIPTOR
from kosong.providers.descriptors.openai import OPENAI_DESCRIPTOR


class ProviderRegistry:
    def __init__(self) -> None:
        self._descriptors: dict[str, ProviderDescriptor] = {}

    def register(self, descriptor: ProviderDescriptor) -> None:
        self._descriptors[descriptor.name] = descriptor

    def get(self, name: str) -> ProviderDescriptor:
        if name not in self._descriptors:
            raise KeyError(f"Provider '{name}' not registered")
        return self._descriptors[name]

    def list_providers(self) -> list[str]:
        return list(self._descriptors.keys())

    def list_models(self, provider: str | None = None) -> list[ModelDescriptor]:
        if provider is not None:
            desc = self.get(provider)
            return list(desc.models)
        models: list[ModelDescriptor] = []
        for desc in self._descriptors.values():
            models.extend(desc.models)
        return models

    def find_model(self, model_id: str) -> tuple[str, ModelDescriptor]:
        for provider_name, desc in self._descriptors.items():
            for model in desc.models:
                if model.id == model_id:
                    return provider_name, model
        raise KeyError(f"Model '{model_id}' not found in any provider")

    def load_builtin_descriptors(self) -> None:
        for descriptor in (
            OPENAI_DESCRIPTOR,
            ANTHROPIC_DESCRIPTOR,
            GOOGLE_DESCRIPTOR,
            DEEPSEEK_DESCRIPTOR,
            OLLAMA_DESCRIPTOR,
        ):
            self.register(descriptor)
