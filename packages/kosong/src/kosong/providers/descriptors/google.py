from kosong.providers.descriptors import ModelDescriptor, ProviderCapabilities, ProviderDescriptor

GOOGLE_DESCRIPTOR = ProviderDescriptor(
    name="google",
    display_name="Google",
    api_base="https://generativelanguage.googleapis.com/v1beta",
    api_key_env="GOOGLE_API_KEY",
    models=[
        ModelDescriptor(
            id="gemini-2.0-flash",
            display_name="Gemini 2.0 Flash",
            context_window=1048576,
            max_output_tokens=8192,
            supports_tools=True,
            supports_vision=True,
            supports_streaming=True,
            input_price_per_million=0.0,
            output_price_per_million=0.0,
        ),
        ModelDescriptor(
            id="gemini-2.0-pro",
            display_name="Gemini 2.0 Pro",
            context_window=1048576,
            max_output_tokens=8192,
            supports_tools=True,
            supports_vision=True,
            supports_streaming=True,
            input_price_per_million=1.25,
            output_price_per_million=10.0,
        ),
    ],
    capabilities=ProviderCapabilities(
        supports_tools=True,
        supports_vision=True,
        supports_streaming=True,
        supports_system_messages=True,
        supports_prompt_caching=False,
    ),
)
