# GLASS-volatility
GLASS (Global Language And Site Scanner) is a Volatility plugin designed by Clayton Wenzel, James Baumhardt, and Nathan Eberly, aiming to swiftly identify and classify malicious domains and unexpected languages within a memory dump, providing users with dynamic insights for forensic investigations.

# Enhancing Volatility for Memory Forensics
GLASS (GLASS Lingual and Suspicious Site Scanner) is a Volatility plugin designed to streamline and enhance memory forensics analysis. It introduces two powerful features to the Volatility framework:

1. Language Identification: This feature leverages the langdetect Python library to identify the language distribution within a specified process. By analyzing the strings within a process dump, GLASS can determine the probability of different languages being used, which can aid in detecting potential malicious activity.
2. Domain Search: GLASS scans memory dumps for the presence of known malicious, fake news, gambling, pornography, phishing, and social media domains. It utilizes frequently updated domain blacklists from various sources, allowing you to quickly identify the presence of unwanted or suspicious domains in memory.

With GLASS, incident responders and malware analysts can significantly reduce the time and effort required to analyze memory dumps. By automating language identification and domain scanning, GLASS provides valuable insights into the potential nature and intent of processes running on a compromised system.

Key Features:

* Language Identification: Identify the language distribution within a specified process, aiding in the detection of potential malicious activity.
* Domain Search: Scan memory dumps for the presence of known malicious, fake news, gambling, pornography, phishing, and social media domains.
* Regularly Updated Blacklists: GLASS leverages frequently updated domain blacklists, ensuring that the analysis is based on the latest threat intelligence.
* Customizable Output: Configure the amount of context displayed around matched domains for better analysis.
* Easy Integration: GLASS is designed as a Volatility plugin, seamlessly integrating with the existing Volatility framework.

GLASS is a valuable addition to the arsenal of digital forensics professionals, providing a streamlined and efficient way to analyze memory dumps and detect potential threats.
