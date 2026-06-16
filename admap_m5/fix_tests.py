import sys

for test_file in ['tests/test_api.py', 'tests/test_api_extra.py']:
    with open(test_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    content = content.replace(
        'async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:',
        'async with ASGITransport(app=app) as transport:\n        async with AsyncClient(transport=transport, base_url="http://test") as client:'
    )
    
    with open(test_file, 'w', encoding='utf-8') as f:
        f.write(content)
