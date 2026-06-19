pdf-report:
  name: Generate PDF Security Report
  runs-on: ubuntu-latest
  needs: [secret-scan, sast, sca, dast]
  if: always()
  steps:
    - name: Checkout repo (pour récupérer le script)
      uses: actions/checkout@v4          # ← remplace le curl

    - name: Install Python dependencies
      run: pip install reportlab

    - name: Download all security artifacts
      uses: actions/download-artifact@v4
      with:
        pattern: '*-report*'
        merge-multiple: true
        path: ./reports

    - name: Generate PDF
      env:
        REPORTS_DIR: ./reports
        OUTPUT_PDF:  security-report-${{ github.run_number }}.pdf
        REPO_NAME:   ${{ github.repository }}
        RUN_ID:      ${{ github.run_number }}
      run: python3 .github/scripts/generate_security_report.py   # ← chemin local

    - name: Upload PDF Report
      uses: actions/upload-artifact@v4
      with:
        name: security-report-pdf
        path: security-report-${{ github.run_number }}.pdf
        retention-days: 90
