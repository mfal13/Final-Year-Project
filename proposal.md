  
## An Accessible File Scanner for Non-Technical Users

## Aim  
To develop a user-friendly tool that combines malware detection and metadata analysis, making cybersecurity accessible to users with minimal technical expertise.

---

## Objectives  
1. **Malware Detection**  
   - Integrate VirusTotal API for multi-engine scanning  
   - Handle API rate limits (4 requests/minute)  
   - Classify files by risk level (✅ Safe / ⚠️ Suspicious)  

2. **Metadata Analysis**  
   - Extract key file attributes:  
     - Timestamps (creation/modification)  
     - Permissions (e.g., `644` = owner read/write, others read-only)  
     - Hashes (SHA-256 for file identification)  
   - Detect extension mismatches (e.g., `.exe` disguised as `.pdf`)  

3. **User Interface**  
   - Build a Flask web interface with:  
     - One-click file upload  
     - Color-coded results (green/red alerts)  
     - Simplified explanations of technical terms  

## Justification  
**Problem**: Existing tools like ExifTool (command-line) and ClamAV (complex setup) exclude non-technical users.  
**Impact**:  
- 76% of home users avoid security tools due to complexity [Silic, 2016]  
- Average malware detection rates below 40% for new threats [Narudin, 2016]  

**Our Solution Addresses**:  
✅ **Accessibility**: Web interface requires no installation  
✅ **Clarity**: Replaces jargon with plain-language results  
✅ **Effectiveness**: Leverages 60+ antivirus engines via VirusTotal  

### Technologies  
| Component          | Technology Stack |  
|--------------------|------------------|  
| Malware Scanning   | VirusTotal API   |  
| Metadata Extraction| Python (`os`, `hashlib`, `magic`) |  
| File Classification| MIME type detection |  
| User Interface     | Flask + HTML/CSS |  

### Development Process  
1. **Sprint 1**: Core functionality (file upload, hash generation)  
2. **Sprint 2**: VirusTotal integration + result processing  
3. **Sprint 3**: Flask UI with responsive design  
4. **Sprint 4**: Usability testing (4 participants)  

---

## Expected Outcomes  
| Deliverable          | Success Metric |  
|----------------------|----------------|  
| Working Prototype    | Scans 20+ file types |  
| Detection Accuracy   | 95% for known malware |  
| Usability            | ≤5 min learning curve |  
| Documentation        | Code comments + user guide |  
