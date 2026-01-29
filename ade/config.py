#!/usr/bin/env python3
"""
Configuration constants and defaults for ADE.
"""

# Version
__version__ = "1.1.0"

# Default credentials (empty = anonymous)
USERNAME_DEFAULT = ""
PASSWORD_DEFAULT = ""

# File paths
USERS_FILE = "users.txt"

# ASCII Art
ASCII_ART_BANNER = r"""                        
                                                         
         .8.          8 888888888o.      8 8888888888   
        .888.         8 8888    `^888.   8 8888         
       :88888.        8 8888        `88. 8 8888         
      . `88888.       8 8888         `88 8 8888         
     .8. `88888.      8 8888          88 8 888888888888 
    .8`8. `88888.     8 8888          88 8 8888         
   .8' `8. `88888.    8 8888         ,88 8 8888         
  .8'   `8. `88888.   8 8888        ,88' 8 8888         
 .888888888. `88888.  8 8888    ,o88P'   8 8888         
.8'       `8. `88888. 8 888888888P'      8 888888888888 
                 
                            by Ｂｌｕｅ  Ｐｈｏ３ｎｉｘ                                      
            """

ASCII_ART_KERBEROS = r"""888  /                    888                                        
888 /     e88~~8e  888-~\ 888-~88e   e88~~8e  888-~\  e88~-_   d88~\ 
888/\    d888  88b 888    888  888b d888  88b 888    d888   i C888   
888  \   8888__888 888    888  8888 8888__888 888    8888   |  Y88b  
888   \  Y888    , 888    888  888P Y888    , 888    Y888   '   888D 
888    \  "88___/  888    888-_88"   "88___/  888     "88_-~  \_88P  
                                                                        """

ASCII_ART_KERBEROS_DETECTED = r"""888~-_               d8                       d8                   888 
888   \   e88~~8e  _d88__  e88~~8e   e88~~\ _d88__  e88~~8e   e88~\888 
888    | d888  88b  888   d888  88b d888     888   d888  88b d888  888 
888    | 8888__888  888   8888__888 8888     888   8888__888 8888  888 
888   /  Y888    ,  888   Y888    , Y888     888   Y888    , Y888  888 
888_-~    "88___/   "88_/  "88___/   "88__/  "88_/  "88___/   "88_/888 
                                                                        """

ASCII_ART_FINISH = r"""Enumeration Finished :)
*   * * *   ** * *** * 
 * * *   **   *        
  *    *        *      
      *                
                *      
       *               
  **               *   
**  *     *   *   *  * 
         *  *         *
                       
                 *   **
     *  *    * *       """

# Section ASCII art templates
SECTION_ART = {
    "domain_discovery": r"""Domain Discovery
*  **  ** *  *  
 **  *     *  * 
         *  *  *
   *            
         *      
          *     
* *    *        
     *      **  
 *         *    
                
               *
    *   *     * """,

    "credentials_check": r"""Credentials Check
* ***  **   **** 
 *   *   *      *
      *   *      
        *        
          *     *
*     *  *  *  * 
   *             
  * **        *  
                 
                 
             *   
 *     *         """,

    "ldap_enumeration": r"""LDAP Enumeration
 **  *   * * *  
*  *  * * *   **
       *    *   
  *        *    
                
*           *   
 *     **       
     **  *     *
              * 
   *            
                
          *  *  """,

    "smb_enumeration": r"""SMB Enumeration
  * *   * * *  
 *   * * *   **
*     *    *   
          *    
* *            
           *   
 *    **       
    **  *     *
             * 
               
               
         *  *  """,

    "user_spraying": r"""AS-REP Roasting & Credential Spraying
*   *    *  * * * * ***  **     * * *
  ** * **    *     *   *   *  **   * 
 *        **            *    *   *   
*        *                *     *    
 *        *                  *       
           *      *     *  *         
                     *               
    *        *      * **           * 
        *                            
     *        *               *     *
                                 *   
   *   *    *      *     *     *  *  """,

    "password_policy": r"""Password Policy Check
*  *  * *   *   * 
 *   * * *   **   
**   *    *       
    *             
            *     
       *          
                  
   *  * *  *    * 
        *  *     *
                  
             *  **
    *  *    * *   """,

    "kerberoasting": r"""Find SPNs (Kerberoasting)
** *        * **  *  * * 
  *   **   * *  **    *  
     *  *          **    
                  *      
     *  *  *  *    *     
                    *    
   *                     
  *    *  * *  *      *  
*                *      *
      *                * 
          *             *
 *           *  *    *   """,

    "bloodhound": r"""Collect BloodHound Data
*   **  *   **   * ** *
 ***     ***  * *      
      *        *     * 
                    * *
        *              
* ** **  *           * 
            *  * * *   
    *           *      
 *        **  *        
                       
             *         """,

    "bloodyad": r"""Check Permissions (bloodyAD)
****   *  *  *     *   * ** 
    * * **    **    ***     
           **   *       *   
                         *  
    *      **   *  *        
*  *                *       
         *             *  * 
  *    *       *  *         
              *      **    *
      *                     
 *                *     *  *
        * *  *              """,

    "adcs": r"""ADCS Enumeration (Certipy)
***  *   * * *    **  *   
      * * *   **    *  *  
   *   *    *        *  * 
*          *              
   *                      
  *         *     *  *    
 *     **                 
     **  *     * * *      
              *          *
                       *  
                 *      **
          *  *      * *   """,
}

# Tag colors for status messages
TAG_COLORS = {
    "[+]": "green",
    "[-]": "red",
    "[!]": "red",
    "[!!!]": "red",
    "[*]": "blue",
    "[INFO]": "blue",
}

# Dependencies required by ADE
DEPENDENCIES = {
    # command_to_check: ("Display Name", "install_key")
    "nmap": ("nmap", "nmap"),
    "nxc": ("NetExec (nxc)", "netexec"),
    "certipy": ("Certipy (ly4k/Certipy)", "certipy"),
    "bloodhound-ce-python": ("BloodHound Python Collector", "bloodhound"),
    "bloodyAD": ("bloodyAD", "bloodyad"),
    "GetNPUsers.py": ("Impacket Script: GetNPUsers.py", "impacket"),
    "getTGT.py": ("Impacket Script: getTGT.py", "impacket"),
    "GetUserSPNs.py": ("Impacket Script: GetUserSPNs.py", "impacket"),
}

# Installation commands for missing dependencies
INSTALL_COMMANDS = {
    "nmap": "sudo apt update && sudo apt install nmap -y   # For Debian/Ubuntu based systems",
    "netexec": "pipx install git+https://github.com/Pennyw0rth/NetExec",
    "certipy": "pipx install certipy-ad",
    "bloodhound": "pipx install bloodhound-ce-python",
    "bloodyad": "pipx install bloodyAD",
    "impacket": "pipx install impacket",
}
