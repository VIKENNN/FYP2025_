import misc_modules
import reconnaissance
import vuln_FINAL
import os
import time
from misc_modules import my_ruler
import Session
from report_generator import ReportGenerator  # Instead of importing the individual functions


def debug_print_results():
    if not Session.session:
        print("[INFO] No results stored yet.")
    else:
        print("\n[DEBUG] Current stored results:\n")
        for i, entry in enumerate(Session.session, 1):
            print(f"{i}. Type: {entry['type']}")
            print(f"   Data: {entry['data']}\n")


def clear_screen():  # clear screen for readability
    os.system("cls" if os.name == "nt" else "clear")


def pause():  # pause input for proper execution
    choice = input("\nPress Enter to return to the menu or 'Q' to quit: ").strip().lower()
    if choice == "q":
        print("\n[+] Exiting... Goodbye!")
        exit()
    clear_screen()


def main():
    clear_screen()
    print("\n" + "=" * 40)
    print("   Welcome to Your Vulnerability Scanner")
    print("=" * 40)
    
    # Ask for target once at the beginning of the session
    target_input = input("\nEnter target URL or hostname to scan: ").strip()
    url, host = misc_modules.clean_target(target_input)  # Get normalized URL + host
    
    
    # Main loop menu
    while True:
        clear_screen()
        print("\n" + "=" * 40)
        print(f"   Target: {host}")
        print("=" * 40)
        print("1. Perform Reconnaissance")
        print("2. Perform Scanning")
        print("3. Generate Report")
        print("4. Quit")
        
        choice = input("\nWhat would you like to do? (1-4): ").strip()
        my_ruler()
        
        if choice == "1":
            print("\n[+] Running reconnaissance...")
            reconnaissance.run_recon_module(url, host)
            time.sleep(1)
            pause()
        
        elif choice == "2":
            print("\n[+] Running vulnerability scanning...")
            vuln_FINAL.run_scan(url)
            time.sleep(1)
            pause()
        
        elif choice == "3":
            print("\n[+] Generating report...\n")
            debug_print_results()
            
            generate = input("Do you wish to generate report now? [Y or N] ")
            if generate.lower() == 'y':
                if not Session.session:
                    print("[!] No scan data available. Please run reconnaissance or vulnerability scans first.\n")
                    pause()
                    continue
                
                # Initialize the report generator
                rg = ReportGenerator()
                
                # Generate report (returns text and PDF elements)
                report_text, pdf_elements = rg.generate_report(
                    session_data=Session.session,
                    target_url=url,
                    target_host=host
                )
                
                # Save PDF report automatically
                rg.save_report(report_text, pdf_elements, target_host=host, target_url=url)
                
                # Optionally save text report separately
                txt_save = input("Do you want to save the text report separately? [Y or N] ")
                if txt_save.lower() == 'y':
                    txt_filename = f"{rg._sanitize_filename(host)}_scan_report.txt"
                    with open(txt_filename, "w", encoding="utf-8") as f:
                        f.write(report_text)
                    print(f"[+] Text report saved as {txt_filename}")
            
            elif generate.lower() == 'n':
                print("[*] Skipping report generation.\n")
            else:
                print("[!] Invalid input. Skipping report generation.\n")
            
            pause()
        
        elif choice == "4":
            print("\n[+] Exiting... Goodbye!")
            break
        
        else:
            print("\n[!] Invalid choice. Please try again.")
            time.sleep(1)


if __name__ == "__main__":
    main()
