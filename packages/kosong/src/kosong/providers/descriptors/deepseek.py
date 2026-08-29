from kosong.providers.descriptors import ModelDescriptor, ProviderCapabilities, ProviderDescriptor

DEEPSEEK_DESCRIPTOR = ProviderDescriptor(
    name="deepseek",
    display_name="DeepSeek",
    api_base="https://api.deepseek.com/v1",
    api_key_env="DEEPSEEK_API_KEY",
    models=[
        ModelDescriptor(
            id="deepseek-chat",
            display_name="DeepSeek Chat",
            context_window=64000,
            max_output_tokens=8192,
            supports_tools=True,
            supports_vision=False,
            supports_streaming=True,
            input_price_per_million=0.14,
            output_price_per_million=0.28,
        ),
        ModelDescriptor(
            id="deepseek-reasoner",
            display_name="DeepSeek Reasoner",
            context_window=64000,
            max_output_tokens=8192,
            supports_tools=False,
            supports_vision=False,
            supports_streaming=True,
            input_price_per_million=0.55,
            output_price_per_million=2.19,
        ),
    ],
    capabilities=ProviderCapabilities(
        supports_tools=True,
        supports_vision=False,
        supports_streaming=True,
        supports_system_messages=True,
        supports_prompt_caching=False,
    ),
)
