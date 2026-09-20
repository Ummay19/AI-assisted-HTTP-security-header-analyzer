from groq import Groq

client = Groq()
models = client.models.list()

for model in models.data:
    print(model.id)