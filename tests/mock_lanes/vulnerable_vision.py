def describe(image_b64):
    return client.responses.create(model="x", input=[{"type":"input_image","image_url":image_b64}])
