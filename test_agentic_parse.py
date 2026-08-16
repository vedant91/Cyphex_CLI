import json
import httpx
from pypdf import PdfReader

def test():
    reader = PdfReader(r'D:\cyphex_v3\docs\Mitigation of Web Application Vulnerabilities.pdf')
    text = '\n'.join([page.extract_text() for page in reader.pages if page.extract_text()])[:6000]
    
    prompt = (
        "You are a Security Parsing Agent. Read the following unstructured document and extract distinct security rules, fix patterns, and vulnerabilities.\n"
        "Respond ONLY with a valid JSON array of objects. Do not include markdown formatting like ```json. Each object must have these exact keys:\n"
        '  "title": string (name of the rule or topic)\n'
        '  "summary": string (1-2 sentence summary)\n'
        '  "cwes": array of strings (e.g., ["CWE-79", "CWE-89"] if applicable, else [])\n'
        '  "content": string (the specific relevant text or code pattern)\n\n'
        f"DOCUMENT:\n{text}\n\nJSON OUTPUT:\n["
    )
    
    r = httpx.post(
        'http://localhost:11434/api/generate',
        json={
            'model': 'llama3.1',
            'prompt': prompt,
            'stream': False,
            'format': 'json',
            'options': {'temperature': 0.1, 'num_predict': 1024, 'num_ctx': 8192}
        },
        timeout=45.0
    )
    
    response_text = r.json().get('response', '').strip()
    print("--- RAW RESPONSE ---")
    print(response_text)
    print("--------------------")
    
    if not response_text.startswith("["):
        response_text = "[" + response_text
        
    try:
        parsed = json.loads(response_text)
        print("SUCCESSFULLY PARSED:", len(parsed), "items")
    except Exception as e:
        print("JSON PARSE ERROR:", str(e))

test()
