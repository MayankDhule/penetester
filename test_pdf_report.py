#!/usr/bin/env python3
"""
Test PDF Report Generation
Verifies that PDF reports are generated correctly
"""

import os
from PyPDF2 import PdfReader

def test_pdf_report():
    """Test that PDF report exists and has content"""
    pdf_path = 'reports/pentest_report.pdf'
    
    # Check file exists
    assert os.path.exists(pdf_path), f"PDF report not found at {pdf_path}"
    
    # Read PDF
    reader = PdfReader(pdf_path)
    
    # Check PDF has pages
    num_pages = len(reader.pages)
    print(f"✓ PDF has {num_pages} pages")
    assert num_pages > 0, "PDF has no pages"
    
    # Extract text from first page (cover page)
    first_page_text = reader.pages[0].extract_text()
    print(f"\n✓ First page content preview:")
    print(first_page_text[:200])
    
    # Verify key sections exist
    assert "PENETRATION TEST REPORT" in first_page_text, "Missing report title"
    assert "darkguard.netlify.app" in first_page_text, "Missing target"
    
    # Check for content in all pages
    full_text = ""
    for page in reader.pages:
        full_text += page.extract_text()
    
    # Verify key sections (case-insensitive for LaTeX formatting)
    full_text_lower = full_text.lower()
    assert "executive summary" in full_text_lower or "assessment" in full_text_lower, "Missing executive summary"
    assert "methodology" in full_text_lower or "phase" in full_text_lower, "Missing methodology"
    assert "finding" in full_text_lower, "Missing findings section"
    assert "technical" in full_text_lower or "reconnaissance" in full_text_lower, "Missing technical appendix"
    
    # Verify vulnerability information
    assert "clickjacking" in full_text_lower, "Missing clickjacking finding"
    assert "medium" in full_text_lower or "critical" in full_text_lower, "Missing severity levels"
    
    print(f"\n✓ PDF contains all required sections")
    print(f"✓ Total pages: {num_pages}")
    print(f"✓ Total characters: {len(full_text)}")
    
    print("\n✅ PDF report test PASSED!")
    return True

if __name__ == '__main__':
    try:
        test_pdf_report()
    except Exception as e:
        print(f"\n❌ PDF report test FAILED: {e}")
        raise
