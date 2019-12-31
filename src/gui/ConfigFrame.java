package gui;

import javax.swing.*;

/**
 * ConfigFrame
 */
public class ConfigFrame extends JFrame {

    public ConfigFrame() {
        initComponents();
    }

    private void initComponents() {
        
        /**
         * Start filteringPanel
         * filteringPanel holds the filtering checkboxes.
         */
        filteringPanel = new JPanel();
        filteringPanel.setBorder(BorderFactory.createTitledBorder("Filtering"));

        inscopeCheckBox = new JCheckBox("Only Process In-scope Items");
        // inscopeCheckBox.addActionListener(new java.awt.event.ActionListener() {
        //     public void actionPerformed(java.awt.event.ActionEvent evt) {
        //         inscopeCheckBoxActionPerformed(evt);
        //     }
        // });

        proxyCheckBox = new JCheckBox("Process New Requests");
        // proxyCheckBox.addActionListener(new java.awt.event.ActionListener() {
        //     public void actionPerformed(java.awt.event.ActionEvent evt) {
        //         proxyCheckBoxActionPerformed(evt);
        //     }
        // });

        repeaterCheckBox = new JCheckBox("Process Requests in Repeater");
        // jCheckBox1.addActionListener(new java.awt.event.ActionListener() {
        //     public void actionPerformed(java.awt.event.ActionEvent evt) {
        //         jCheckBox1ActionPerformed(evt);
        //     }
        // });

        // Create a BoxLayout to hold the checkboxees on top of each other.
        BoxLayout filteringLayout = new BoxLayout(filteringPanel, BoxLayout.Y_AXIS);
        filteringPanel.setLayout(filteringLayout);
        // Add the checkboxes for the filteringPanel with gaps.
        filteringPanel.add(inscopeCheckBox);
        filteringPanel.add(Box.createVerticalGlue());
        filteringPanel.add(proxyCheckBox);
        filteringPanel.add(Box.createVerticalGlue());
        filteringPanel.add(repeaterCheckBox);
        filteringPanel.add(Box.createVerticalGlue());
        /**
         * End filteringPanel
         */
    }

    // GUI Variables
    private JCheckBox inscopeCheckBox;
    private JCheckBox repeaterCheckBox;
    private JPanel filteringPanel;
    private JCheckBox proxyCheckBox;
}