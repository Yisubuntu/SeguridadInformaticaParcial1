# Ejercicio 2
from Crypto.Util import number as n
import hashlib as hl
from PyPDF2 import PdfWriter, PdfReader
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

class PDFSigner:
    def __init__(self, bits=1024):
        self.bits = bits
        self.generate_keys()

    def generate_keys(self):
        # Generación de claves para Alice
        self.pA = n.getPrime(self.bits)
        self.qA = n.getPrime(self.bits)
        self.nA = self.pA * self.qA
        self.phiA = (self.pA - 1) * (self.qA - 1)
        self.e = 65537
        self.dA = n.inverse(self.e, self.phiA)

    def hash_pdf(self, ruta_archivo_pdf):
        hash_pdf = hl.sha256()
        with open(ruta_archivo_pdf, 'rb') as archivo:
            for fragmento in iter(lambda: archivo.read(4096), b''):
                hash_pdf.update(fragmento)
        self.hash_int = int.from_bytes(hash_pdf.digest(), byteorder='big')

    def sign_pdf(self):
        self.hash_firmado_Alice = pow(self.hash_int, self.dA, self.nA)

    def validate_signature(self):
        hash_original = int.from_bytes(hl.sha256(str(self.hash_firmado_Alice).encode()).digest(), byteorder='big')
        hash_validacion = pow(self.hash_firmado_Alice, self.e, self.nA)
        return hash_original == hash_validacion

    def add_signature_to_pdf(self, ruta_pdf, firmante):
        lector = PdfReader(ruta_pdf)
        escritor = PdfWriter()
        for página in lector.pages:
            escritor.add_page(página)
        nueva_ruta_archivo = f"NDA_firma_{firmante}.pdf"
        lienzo = canvas.Canvas(nueva_ruta_archivo, pagesize=letter)
        lienzo.drawString(50, 50, str(self.hash_firmado_Alice))
        lienzo.save()
        return nueva_ruta_archivo

if __name__ == "__main__":
    pdf_signer = PDFSigner()
    pdf_signer.hash_pdf("NDA.pdf")
    pdf_signer.sign_pdf()
    is_valid = pdf_signer.validate_signature()
    print(f"La Autoridad Certificadora (AC) ha verificado la firma de Alice: {'Sí' if is_valid else 'No'}.")
    firma_pdf = pdf_signer.add_signature_to_pdf("NDA.pdf", "Alice")
    print(f"PDF firmado guardado como: {firma_pdf}")
