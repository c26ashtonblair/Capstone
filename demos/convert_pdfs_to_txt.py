# convert_pdfs_to_txt.py
from pathlib import Path
from PyPDF2 import PdfReader

pdf_folder = Path("docs")

for pdf_path in pdf_folder.glob("*.pdf"):
    txt_path = pdf_path.with_suffix(".txt")
    try:
        reader = PdfReader(str(pdf_path))
        text = ""
        for page in reader.pages:
            text += page.extract_text() or ""
        txt_path.write_text(text.strip())
        print(f"✅ Converted: {pdf_path.name} → {txt_path.name}")
    except Exception as e:
        print(f"⚠️ Error converting {pdf_path.name}: {e}")
