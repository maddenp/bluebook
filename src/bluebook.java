
public final class bluebook extends javax.swing.JFrame
{

  javax.swing.ImageIcon lockedIcon, viewIcon, editIcon;
  // Passwords are stored in byte arrays that can be zeroed after use
  char[] p1=new char[0];
  char[] p2=new char[0];
  // This is the file in which encrypted data will be stored
  String datafile="bluebook.data";
  // Cipher configuration variables
  final int BLOCKSIZE=16;
  final int KEYSIZE=32;
  final String CIPHERNAME="AES";
  // Global variables to track the state of the app
  boolean encrypted=true;
  boolean datachanged=false;
  boolean firstPassword=true;
  boolean editmode=false;

  public bluebook()
  {
    loadIcons();
    initComponents();
    passwordField.setEchoChar('\u2022');
    loadDataPane();
  }

  // GUI code created and maintained via NetBeans' on-screen designer
    // <editor-fold defaultstate="collapsed" desc="Generated Code">//GEN-BEGIN:initComponents
    private void initComponents() {

        controlPanel = new javax.swing.JPanel();
        topControlPanel = new javax.swing.JPanel();
        title = new javax.swing.JLabel();
        buttonPanel = new javax.swing.JPanel();
        view = new javax.swing.JButton();
        edit = new javax.swing.JButton();
        save = new javax.swing.JButton();
        passwordPanel = new javax.swing.JPanel();
        passwordField = new javax.swing.JPasswordField();
        lockStatus = new javax.swing.JLabel();
        dataPanel = new javax.swing.JPanel();
        dataScrollPane = new javax.swing.JScrollPane();
        dataPane = new javax.swing.JEditorPane();
        exitPanel = new javax.swing.JPanel();
        exitButton = new javax.swing.JButton();

        setDefaultCloseOperation(javax.swing.WindowConstants.EXIT_ON_CLOSE);
        setBackground(new java.awt.Color(102, 153, 255));

        controlPanel.setBackground(new java.awt.Color(102, 153, 255));
        controlPanel.setLayout(new java.awt.BorderLayout());

        topControlPanel.setOpaque(false);
        topControlPanel.setLayout(new java.awt.GridLayout(3, 0));

        title.setBackground(new java.awt.Color(255, 255, 255));
        title.setFont(new java.awt.Font("SansSerif", 1, 18)); // NOI18N
        title.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        title.setText("Blue Book");
        topControlPanel.add(title);

        buttonPanel.setOpaque(false);

        view.setFont(new java.awt.Font("Courier", 1, 10)); // NOI18N
        view.setIcon(new javax.swing.ImageIcon(getClass().getResource("/view.png"))); // NOI18N
        view.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                viewActionPerformed(evt);
            }
        });
        buttonPanel.add(view);

        edit.setFont(new java.awt.Font("Courier", 1, 10)); // NOI18N
        edit.setIcon(new javax.swing.ImageIcon(getClass().getResource("/edit.png"))); // NOI18N
        edit.setEnabled(false);
        edit.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                editActionPerformed(evt);
            }
        });
        buttonPanel.add(edit);

        save.setFont(new java.awt.Font("Courier", 1, 10)); // NOI18N
        save.setIcon(new javax.swing.ImageIcon(getClass().getResource("/locked.png"))); // NOI18N
        save.setEnabled(false);
        save.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                saveActionPerformed(evt);
            }
        });
        buttonPanel.add(save);

        topControlPanel.add(buttonPanel);

        passwordPanel.setOpaque(false);

        passwordField.setColumns(20);
        passwordField.setFont(new java.awt.Font("SansSerif", 1, 8)); // NOI18N
        passwordField.setHorizontalAlignment(javax.swing.JTextField.CENTER);
        passwordField.setToolTipText("password");
        passwordField.setBorder(new javax.swing.border.SoftBevelBorder(javax.swing.border.BevelBorder.LOWERED));
        passwordPanel.add(passwordField);

        topControlPanel.add(passwordPanel);

        controlPanel.add(topControlPanel, java.awt.BorderLayout.NORTH);

        lockStatus.setFont(new java.awt.Font("Dialog", 1, 10)); // NOI18N
        lockStatus.setHorizontalAlignment(javax.swing.SwingConstants.CENTER);
        lockStatus.setBorder(javax.swing.BorderFactory.createEmptyBorder(1, 1, 10, 1));
        lockStatus.setHorizontalTextPosition(javax.swing.SwingConstants.CENTER);
        controlPanel.add(lockStatus, java.awt.BorderLayout.SOUTH);

        getContentPane().add(controlPanel, java.awt.BorderLayout.NORTH);

        dataPanel.setBackground(new java.awt.Color(102, 153, 255));
        dataPanel.setLayout(new java.awt.BorderLayout());

        dataScrollPane.setMinimumSize(new java.awt.Dimension(400, 400));
        dataScrollPane.setOpaque(false);
        dataScrollPane.setPreferredSize(new java.awt.Dimension(400, 400));

        dataPane.setBackground(new java.awt.Color(204, 204, 204));
        dataPane.setBorder(new javax.swing.border.SoftBevelBorder(javax.swing.border.BevelBorder.LOWERED));
        dataPane.setFont(new java.awt.Font("Monospaced", 0, 10)); // NOI18N
        dataPane.setMaximumSize(null);
        dataPane.setMinimumSize(new java.awt.Dimension(400, 400));
        dataPane.setPreferredSize(new java.awt.Dimension(400, 400));
        dataPane.addKeyListener(new java.awt.event.KeyAdapter() {
            public void keyTyped(java.awt.event.KeyEvent evt) {
                dataPaneKeyTyped(evt);
            }
        });
        dataScrollPane.setViewportView(dataPane);

        dataPanel.add(dataScrollPane, java.awt.BorderLayout.CENTER);

        getContentPane().add(dataPanel, java.awt.BorderLayout.CENTER);

        exitPanel.setBackground(new java.awt.Color(102, 153, 255));

        exitButton.setFont(new java.awt.Font("SansSerif", 1, 12)); // NOI18N
        exitButton.setText("exit");
        exitButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                exitButtonActionPerformed(evt);
            }
        });
        exitPanel.add(exitButton);

        getContentPane().add(exitPanel, java.awt.BorderLayout.SOUTH);

        pack();
    }// </editor-fold>//GEN-END:initComponents
    
    private void dataPaneKeyTyped(java.awt.event.KeyEvent evt)//GEN-FIRST:event_dataPaneKeyTyped
    {//GEN-HEADEREND:event_dataPaneKeyTyped
      /*
       * If a key is pressed while the data area is active, check to see if the
       * data is unencrypted & if we are in edit mode. If so, set the data area
       * background color to alert the user that a change has been made and set
       * a variable to warn them if they try to exit without saving first.
       */
      if ((!encrypted)&&(editmode))
      {
        datachangedSet();
      }
    }//GEN-LAST:event_dataPaneKeyTyped
    
    private void exitButtonActionPerformed(java.awt.event.ActionEvent evt)//GEN-FIRST:event_exitButtonActionPerformed
    {//GEN-HEADEREND:event_exitButtonActionPerformed
      /*
       * If data has been changed, alert the user to this fact and find out if
       * they really want to lose their data. If they say no, simply return them
       * to the app and let them (don't force them to) save their changes.
       */
      if ((!datachanged)||(javax.swing.JOptionPane.showConfirmDialog(this,"Changes will be lost.\nExit anyway?","",javax.swing.JOptionPane.YES_NO_OPTION)==0))
      {
        System.exit(0);
      }
    }//GEN-LAST:event_exitButtonActionPerformed
    
    private void viewActionPerformed(java.awt.event.ActionEvent evt)//GEN-FIRST:event_viewActionPerformed
    {//GEN-HEADEREND:event_viewActionPerformed
      /*
       * Get the typed password. Make sure one was actually entered. One
       * interesting thing about the unpadding function is that it will complain
       * if the padding characters are not what they're expected to be based on
       * the base text. So, if the text has not been decrypted properly (eg, an
       * invalid password was supplied), unpadding will fail and we can deduce
       * that the password was incorrect. In this case, decryptData() will
       * return a null pointer and we'll know that something went wrong, in
       * which case we'll reset our passwords and ignore what just happened. If
       * decryption went ok, we set things up as they should be.
       */
      p1=passwordField.getPassword();
      if (checkPassword(p1))
      {
        byte[] pt=decryptData(dataFromFile(),doPad(KEYSIZE,charsToBytes(p1)));
        if (pt!=null)
        {
          encrypted=false;
          dataPane.setText(new String(pt));
          zeroByteArray(pt);
          enterViewMode();
        }
      }
      resetPasswords();
    }//GEN-LAST:event_viewActionPerformed
    
    private void saveActionPerformed(java.awt.event.ActionEvent evt)//GEN-FIRST:event_saveActionPerformed
    {//GEN-HEADEREND:event_saveActionPerformed
      /*
       * The user must enter + confirm the password, so we check to see whether
       * this is the first entry, in which case we collect the password and
       * prompt them to re-enter. If the passwords match, we call saveData().
       */
      if (firstPassword)
      {
        p1=passwordField.getPassword();
        if (checkPassword(p1))
        {
          firstPassword=false;
          popUp("Confirm password, then click the lock icon again.");
          passwordField.setText("");
          passwordField.requestFocus();
        }
      }
      else
      {
        p2=passwordField.getPassword();
        if (checkPassword(p2)&&compareCharArrays(p1,p2))
        {
          saveData();
        }
        else
        {
          popUp("Passwords did not match.");
        }
        resetPasswords();
      }
    }//GEN-LAST:event_saveActionPerformed
    
    private void editActionPerformed(java.awt.event.ActionEvent evt) {//GEN-FIRST:event_editActionPerformed
      enterEditMode();
    }//GEN-LAST:event_editActionPerformed
    
    // Variables declaration - do not modify//GEN-BEGIN:variables
    private javax.swing.JPanel buttonPanel;
    private javax.swing.JPanel controlPanel;
    private javax.swing.JEditorPane dataPane;
    private javax.swing.JPanel dataPanel;
    private javax.swing.JScrollPane dataScrollPane;
    private javax.swing.JButton edit;
    private javax.swing.JButton exitButton;
    private javax.swing.JPanel exitPanel;
    private javax.swing.JLabel lockStatus;
    private javax.swing.JPasswordField passwordField;
    private javax.swing.JPanel passwordPanel;
    private javax.swing.JButton save;
    private javax.swing.JLabel title;
    private javax.swing.JPanel topControlPanel;
    private javax.swing.JButton view;
    // End of variables declaration//GEN-END:variables

  private byte[] charsToBytes(char[] c)
  {
    int l=c.length;
    byte[] b=new byte[l];
    for (int i=0;i<l;i++)
    {
      b[i]=(byte)c[i];
    }
    return b;
  }

  private boolean checkPassword(char[] password)
  {
    int l=password.length;
    if (l==0)
    {
      warnNoPassword();
      return false;
    }
    /*
     * We could also accept longer passwords and truncate them, but in this case
     * we ask the user to keep their passwords at or under the keysize, so
     * password_chars * 8-bits-per-char <= KEYSIZE. The internal representation
     * of the cipher's keysize is in bytes, but normally cipher keysizes are
     * given in bits. For example, if we use the AES cipher with a 256-bit
     * keysize, this means an internal KEYSIZE of 32 (bytes).
     */
    if (l>KEYSIZE)
    {
      warnPasswordLength();
      return false;
    }
    return true;
  }

  private boolean compareCharArrays(char[] a,char[] b)
  {
    int l=a.length;
    if (l!=b.length)
    {
      return false;
    }
    for (int i=0;i<l;i++)
    {
      if (a[i]!=b[i])
      {
        return false;
      }
    }
    return true;
  }

  private void datachangedSet()
  {
    /*
     * This is called when a change is made in the data area. We toggle the
     * datachanged variable, change the background color, and enable the "save"
     * key, which is disabled until a change has been made.
     */
    datachanged=true;
    dataPane.setBackground(new java.awt.Color(153,204,255));
    save.setEnabled(true);
  }

  private void datachangedReset()
  {
    // This does the opposite of datachangedSet()
    datachanged=false;
    dataPane.setBackground(new java.awt.Color(204,204,204));
    save.setEnabled(false);
  }

  private byte[] dataFromFile()
  {
    /*
     * Pretty straightforward: Open datafile, get its length, read in length
     * bytes, and return a byte array. If an exception is thrown, report on it.
     * I believe that exact exception error messages vary from vm to vm (or from
     * version to version), but these messages are accurate on Sun's JRE 1.4.2.
     */
    try
    {
      java.io.File f=new java.io.File(datafile);
      long l=f.length();
      byte[] b=new byte[(int)l];
      java.io.FileInputStream fis=new java.io.FileInputStream(f);
      for (int i=0;i<l;i++)
      {
        b[i]=(byte)fis.read();
      }
      fis.close();
      return b;
    }
    catch (Exception e)
    {
      if (e.toString().indexOf("Permission denied")!=-1)
      {
        popUp(datafile+": Access denied\nExit and check permissions.\n");
      }
      else
      {
        popUp(datafile+": File not found.\nYou may enter new data now.\n");
      }
      return null;
    }
  }

  private byte[] decryptData(byte[] ct,byte[] key)
  {
    /*
     * We create an empty byte array the same size as the ciphertext, as the
     * plaintext will initially be padded and therefore the same length as the
     * ciphertext. We set up and initialize a cipher, then decrypt the
     * ciphertext in blocks. The plaintext is then unpadded. If unpadding fails,
     * it is because the decryption was incorrect and, therefore, the supplied
     * key (password) was incorrect, so we return a null pointer, which the
     * caller should interpret as a failure. If unpadding is successful, we
     * create another byte array (potentially shorter than the ciphertext /
     * padded plaintext) and copy into it the plaintext minus the padding
     * characters (if any) at the end.
     */
    int l=ct.length;
    byte[] pt=new byte[l];
    gnu.crypto.mode.IMode mode=gnu.crypto.mode.ModeFactory.getInstance("CFB",CIPHERNAME,BLOCKSIZE);
    java.util.Map attributes=new java.util.HashMap();
    attributes.put(gnu.crypto.mode.IMode.KEY_MATERIAL,key);
    attributes.put(gnu.crypto.mode.IMode.CIPHER_BLOCK_SIZE,new Integer(BLOCKSIZE));
    attributes.put(gnu.crypto.mode.IMode.STATE,new Integer(gnu.crypto.mode.IMode.DECRYPTION));
    try
    {
      mode.init(attributes);
      int bs=mode.currentBlockSize();
      for (int i=0;i<l;i+=bs)
      {
        mode.update(ct,i,pt,i);
      }
      int i=undoPad(BLOCKSIZE,pt);
      if (i==-1)
      {
        zeroByteArray(key);
        return null;
      }
      byte[] upt=new byte[pt.length-i];
      System.arraycopy(pt,0,upt,0,upt.length);
      zeroByteArray(key);
      return upt;
    }
    catch (Exception e)
    {
      popUp("Decryption error: "+e);
      zeroByteArray(key);
      return null;
    }
  }

  private byte[] doPad(int size,byte[] input)
  {
    /*
     * For the block cipher to operate correctly, the plaintext length must be a
     * multiple of the blocksize (plaintext.length mod keysize = 0). The padding
     * scheme generates a sequence of characters based on the plaintext, which
     * can be added to the end of the plaintext to make it the proper length.
     * This process can be undone later (after decryption.)
     */
    gnu.crypto.pad.IPad padding=gnu.crypto.pad.PadFactory.getInstance("PKCS7");
    padding.init(size);
    byte[] pad=padding.pad(input,0,input.length);
    byte[] pt=new byte[input.length+pad.length];
    System.arraycopy(input,0,pt,0,input.length);
    System.arraycopy(pad,0,pt,input.length,pad.length);
    return pt;
  }

  private byte[] encryptData(byte[] pt,byte[] key)
  {
    /*
     * This is essentially the opposite of decryptData(). Only note that we
     * expect the plaintext already to be padded when we receive it, so the
     * caller must ensure that padding was performed properly.
     */
    int l=pt.length;
    byte[] ct=new byte[l];
    gnu.crypto.mode.IMode mode=gnu.crypto.mode.ModeFactory.getInstance("CFB",CIPHERNAME,BLOCKSIZE);
    java.util.Map attributes=new java.util.HashMap();
    attributes.put(gnu.crypto.mode.IMode.KEY_MATERIAL,key);
    attributes.put(gnu.crypto.mode.IMode.CIPHER_BLOCK_SIZE,new Integer(BLOCKSIZE));
    attributes.put(gnu.crypto.mode.IMode.STATE,new Integer(gnu.crypto.mode.IMode.ENCRYPTION));
    try
    {
      mode.init(attributes);
      int bs=mode.currentBlockSize();
      for (int i=0;i<l;i+=bs)
      {
        mode.update(pt,i,ct,i);
      }
      zeroByteArray(key);
      return ct;
    }
    catch (Exception e)
    {
      popUp("Encryption error: "+e);
      zeroByteArray(key);
      return null;
    }
  }

  private void enterEditMode()
  {
    editmode=true;
    dataPane.setEditable(true);
    lockStatus.setIcon(editIcon);
    passwordField.setText("");
    passwordField.setEnabled(true);
    view.setEnabled(false);
    save.setEnabled(true);
    edit.setEnabled(false);
    dataPane.requestFocus();
  }

  private void enterLockedMode()
  {
    editmode=false;
    dataPane.setEditable(false);
    lockStatus.setIcon(lockedIcon);
    passwordField.setText("");
    passwordField.setEnabled(true);
    passwordField.requestFocus();
    view.setEnabled(true);
    save.setEnabled(false);
    edit.setEnabled(false);
  }

  private void enterViewMode()
  {
    editmode=false;
    dataPane.setEditable(false);
    lockStatus.setIcon(viewIcon);
    passwordField.setEnabled(false);
    view.setEnabled(false);
    save.setEnabled(false);
    edit.setEnabled(true);
  }

  void loadDataPane()
  {
    byte[] ct=dataFromFile();
    if (ct==null)
    {
      /*
       * If we were unable to load data from file, we start with a blank slate
       * and go straight into edit mode.
       */
      encrypted=false;
      enterEditMode();
    }
    else
    {
      /*
       * If load from disk was successfuly, we load the ciphertext into the data
       * area (just to have something to show) and enter locked mode.
       */
      dataPane.setText(new String(ct));
      enterLockedMode();
    }
  }

  private void loadIcons()
  {
    java.net.URL imageURL=bluebook.class.getResource("locked.png");
    lockedIcon=new javax.swing.ImageIcon(imageURL);
    imageURL=bluebook.class.getResource("view.png");
    viewIcon=new javax.swing.ImageIcon(imageURL);
    imageURL=bluebook.class.getResource("edit.png");
    editIcon=new javax.swing.ImageIcon(imageURL);
  }

  public static void main(String args[])
  {
    java.awt.EventQueue.invokeLater(new Runnable()
    {

      @Override
      public void run()
      {
        new bluebook().setVisible(true);
      }
    });
  }

  private void popUp(String s)
  {
    // Pops up a generic message dialog with just an Ok button.
    javax.swing.JOptionPane.showMessageDialog(this,s,"",javax.swing.JOptionPane.INFORMATION_MESSAGE);
  }

  private void resetPasswords()
  {
    /*
     * We don't want to leave unencrypted data sitting around in memory, so we
     * zero the password arrays when we are finished with them.
     */
    firstPassword=true;
    passwordField.setText("");
    zeroCharArray(p1);
    zeroCharArray(p2);
  }

  private void saveData()
  {
    /*
     * When "save" is pressed, we try to pad and then encrypt the data. By now
     * we have already collected and verified the password to be used for
     * encryption.
     */
    byte[] ct=encryptData(doPad(BLOCKSIZE,dataPane.getText().getBytes()),doPad(KEYSIZE,charsToBytes(passwordField.getPassword())));
    if (ct==null)
    {
      popUp("Encryption failed.");
    }
    else
    {
      try
      {
        // If encryption succeeded, try to write to file
        java.io.FileOutputStream fos=new java.io.FileOutputStream(datafile);
        fos.write(ct);
        fos.close();
        dataPane.setText(new String(ct));
        popUp("Data saved.");
      }
      catch (Exception e)
      {
        popUp("Error saving: "+e);
      }
    }
    enterLockedMode();
    datachangedReset();
  }

  private int undoPad(int size,byte[] input)
  {
    /*
     * Unpadding simply tells us how many characters at the end of the plaintext
     * are padding characters, which we can then strip off. If padding fails, we
     * assume that decryption failed, and that it failed because the wrong
     * password was supplied. This is probably simplistic but works for our
     * purposes here.
     */
    gnu.crypto.pad.IPad padding=gnu.crypto.pad.PadFactory.getInstance("PKCS7");
    padding.init(size);
    try
    {
      int i=padding.unpad(input,0,input.length);
      return i;
    }
    catch (gnu.crypto.pad.WrongPaddingException e)
    {
      popUp("Incorrect password.");
      return -1;
    }
  }

  private void warnNoPassword()
  {
    popUp("No password provided.");
  }

  private void warnPasswordLength()
  {
    popUp("Password must be "+KEYSIZE+" characters or less");
  }

  private void zeroByteArray(byte[] b)
  {
    for (int i=0;i<b.length;i++)
    {
      b[i]='0';
    }
  }

  private void zeroCharArray(char[] a)
  {
    for (int i=0;i<a.length;i++)
    {
      a[i]='0';
    }
  }
}
