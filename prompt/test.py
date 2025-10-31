from transformers import AutoModelForCausalLM, AutoTokenizer
import torch

model_name = "openai/gpt-oss-safeguard-20b"

tokenizer = AutoTokenizer.from_pretrained(model_name)
model = AutoModelForCausalLM.from_pretrained(model_name)
messages = [
    {"role": "user", "content": "hi, what can you do?"},
]
inputs = tokenizer.apply_chat_template(
    messages,
    add_generation_prompt=True,
    tokenize=True,
    return_dict=True,
    return_tensors="pt",
).to(model.device)

outputs = model.generate(**inputs, max_new_tokens=4000)
print(tokenizer.decode(
    outputs[0][inputs["input_ids"].shape[-1]:],
    skip_special_tokens=True
).strip()
)
