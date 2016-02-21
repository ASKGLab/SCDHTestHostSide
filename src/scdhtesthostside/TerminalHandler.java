/*
 * 3-Clause BSD License
 * Copyright (c) 2016, Thotheolh
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without 
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, 
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice, 
 * this list of conditions and the following disclaimer in the documentation and
 * /or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors 
 * may be used to endorse or promote products derived from this software without 
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE 
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
 * POSSIBILITY OF SUCH DAMAGE.
 */
package scdhtesthostside;

import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;
import javax.smartcardio.TerminalFactory;

/**
 *
 * @author Thotheolh
 */
public class TerminalHandler {

    // Card Protocol Flags
    public static String CARD_PROTO_T_0 = "T=0";
    public static String CARD_PROTO_T_1 = "T=1";
    public static String CARD_PROTO_T_CL = "T=CL";
    public static String CARD_PROTO_ANY = "*";

    private TerminalFactory factory = null;
    private List<CardTerminal> terminals = null;

    public TerminalHandler() {

    }

    public void loadDefaultTerminal() {
        try {
            setFactory(TerminalFactory.getDefault());
            setTerminals(getFactory().terminals().list());
        } catch (CardException ex) {
            Logger.getLogger(TerminalHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public void printTerminalInfo(List<CardTerminal> terminals) {
        System.out.println("Available Terminals: \r\n");

        for (int i = 0; i < terminals.size(); i++) {
            try {
                System.out.println("Terminal ID: " + i);
                System.out.println("\tTerminal Name: " + terminals.get(i).getName());
                System.out.println("\tHas Card     : " + terminals.get(i).isCardPresent());
            } catch (CardException ex) {
                Logger.getLogger(TerminalHandler.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    public TerminalFactory getFactory() {
        return factory;
    }

    public void setFactory(TerminalFactory factory) {
        this.factory = factory;
    }

    public List<CardTerminal> getTerminals() {
        return terminals;
    }

    public void setTerminals(List<CardTerminal> terminals) {
        this.terminals = terminals;
    }

    public Card getCard(String cardProtocol, int terminalId) {
        try {
            return terminals.get(terminalId).connect(cardProtocol);
        } catch (CardException ex) {
            Logger.getLogger(TerminalHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

}
