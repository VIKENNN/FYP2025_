import misc_modules
import reconnaissance
import vuln_THEONE
import os
import time

def clear_screen(): #clear screen for readability
    os.system("cls" if os.name == "nt" else "clear")

def pause(): #pause input for proper execution
    choice = input("\nPress Enter to return to the menu or 'Q' to quit: ").strip().lower()
    if choice == "q":
        print("\n[+] Exiting... Goodbye!")
        exit()
    clear_screen()

def main():
    while True:
        clear_screen()
        print("\n" + "="*40)
        print("   Welcome to Your Vulnerability Scanner")
        print("="*40)
        print("1. Perform Reconnaissance")
        print("2. Perform Scanning")
        print("3. Generate Report")
        print("4. Quit")

        choice = input("\nWhat would you like to do? (1-4): ").strip()

        if choice == "1":
            reconnaissance.run_recon_module()
            time.sleep(1)
            pause()
        elif choice == "2":
            vuln_THEONE.run_scan()
            time.sleep(1)
            pause()
        elif choice == "3":
            print("Nothing here yet....")
            time.sleep(1)
            pause()
        elif choice == "4":
            print("\n[+] Exiting... Goodbye!")
            break
        else:
            print("\n[!] Invalid choice. Please try again.")
            time.sleep(1)

if __name__ == "__main__":
    main()
