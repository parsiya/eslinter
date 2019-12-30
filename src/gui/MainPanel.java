package gui;

import javax.swing.*;
import javax.swing.BorderFactory;

import static burp.BurpExtender.callbacks;

/**
 * MainPanel
 */
public class MainPanel {

    public JSplitPane mainPanel;

    public MainPanel() {
        initComponents();
    }

    private void initComponents() {
        mainPanel = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        configPanel = new JPanel();
        
        searchButton = new JButton("Search");
        searchTextField = new JTextField("Search");
        // searchTextField.addActionListener(new java.awt.event.ActionListener() {
        //     public void actionPerformed(java.awt.event.ActionEvent evt) {
        //         searchTextFieldActionPerformed(evt);
        //     }
        // });

        /**
         * Start filteringPanel to hold the checkboxes.
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
        // Add the checkboxes for the filteringPanel.
        filteringPanel.add(inscopeCheckBox);
        filteringPanel.add(proxyCheckBox);
        filteringPanel.add(repeaterCheckBox);
        /**
         * End filteringPanel
         */


        beautifiedJSStoragePathButton = new JButton("Beautified JavaScript Storage Path");

        esLintConfigPathButton = new JButton("ESLint Config Path");

        esLintBinaryPathButton = new JButton("ESLint Binary Path");
        // esLintBinaryPathButton.addActionListener(new java.awt.event.ActionListener() {
        //     public void actionPerformed(java.awt.event.ActionEvent evt) {
        //         esLintBinaryPathButtonActionPerformed(evt);
        //     }
        // });

        esLintOutputPathButton = new JButton("ESLint Output Path");
        // esLintOutputPathButton.addActionListener(new java.awt.event.ActionListener() {
        //     public void actionPerformed(java.awt.event.ActionEvent evt) {
        //         esLintOutputPathButtonActionPerformed(evt);
        //     }
        // });

        loadConfigButton = new JButton("Load Config");

        saveConfigButton = new JButton("Save Config");

        processToggleButton = new JToggleButton("Process", false);

        // processToggleButton.addActionListener(new java.awt.event.ActionListener() {
        //     public void actionPerformed(java.awt.event.ActionEvent evt) {
        //         processToggleButtonActionPerformed(evt);
        //     }
        // });



        GroupLayout configPanelLayout = new GroupLayout(configPanel);
        configPanel.setLayout(configPanelLayout);
        configPanelLayout.setHorizontalGroup(
            configPanelLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(configPanelLayout.createSequentialGroup()
                .addGroup(configPanelLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addGroup(configPanelLayout.createSequentialGroup()
                        .addGroup(configPanelLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                            .addGroup(configPanelLayout.createSequentialGroup()
                                .addComponent(filteringPanel, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(configPanelLayout.createParallelGroup(GroupLayout.Alignment.LEADING, false)
                                    .addComponent(esLintOutputPathButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(beautifiedJSStoragePathButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(esLintConfigPathButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                                    .addComponent(esLintBinaryPathButton, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
                                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                                .addGroup(configPanelLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                                    .addComponent(loadConfigButton)
                                    .addComponent(saveConfigButton)))
                            .addComponent(processToggleButton, GroupLayout.PREFERRED_SIZE, 600, GroupLayout.PREFERRED_SIZE))
                        .addGap(0, 6, Short.MAX_VALUE))
                    .addComponent(searchTextField))
                .addContainerGap())
        );
        configPanelLayout.setVerticalGroup(
            configPanelLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(configPanelLayout.createSequentialGroup()
                .addGap(6, 6, 6)
                .addComponent(searchTextField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addGroup(configPanelLayout.createParallelGroup(GroupLayout.Alignment.TRAILING, false)
                    .addComponent(filteringPanel, GroupLayout.Alignment.LEADING, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
                    .addGroup(GroupLayout.Alignment.LEADING, configPanelLayout.createSequentialGroup()
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(configPanelLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                            .addComponent(beautifiedJSStoragePathButton)
                            .addComponent(loadConfigButton))
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addGroup(configPanelLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                            .addComponent(esLintConfigPathButton)
                            .addComponent(saveConfigButton))
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(esLintBinaryPathButton)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(esLintOutputPathButton)))
                .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                .addComponent(processToggleButton)
                .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        mainPanel.setLeftComponent(configPanel);

        // topPanel = new JPanel();
        // GroupLayout layout = new GroupLayout(topPanel);
        // topPanel.setLayout(layout);

        // layout.setHorizontalGroup(
        //     layout.createParallelGroup(GroupLayout.Alignment.LEADING)
        //     .addComponent(configPanel, GroupLayout.DEFAULT_SIZE, GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE)
        // );
        // layout.setVerticalGroup(
        //     layout.createParallelGroup(GroupLayout.Alignment.LEADING)
        //     .addGroup(layout.createSequentialGroup()
        //         .addGap(26, 26, 26)
        //         .addComponent(configPanel, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
        //         .addContainerGap(269, Short.MAX_VALUE))
        // );


    }

    // GUI Variables
    private JButton beautifiedJSStoragePathButton;
    private JPanel configPanel;
    private JButton esLintBinaryPathButton;
    private JButton esLintConfigPathButton;
    private JButton esLintOutputPathButton;
    private JCheckBox inscopeCheckBox;
    private JCheckBox repeaterCheckBox;
    private JPanel filteringPanel;
    private JButton loadConfigButton;
    private JToggleButton processToggleButton;
    private JCheckBox proxyCheckBox;
    private JButton saveConfigButton;
    private JTextField searchTextField;
    private JButton searchButton;


}