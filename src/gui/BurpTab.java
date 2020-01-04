package gui;

import static burp.BurpExtender.extensionConfig;

import java.awt.Dimension;
import java.io.File;

import javax.swing.GroupLayout;
import javax.swing.JButton;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSeparator;
import javax.swing.JSplitPane;
import javax.swing.JTextField;
import javax.swing.JToggleButton;
import javax.swing.LayoutStyle;
import javax.swing.SwingConstants;

import linttable.LintTable;
import utils.FileChooser;
import utils.StringUtils;

/**
 * BurpTab
 */
public class BurpTab {

    public JSplitPane panel;
    public LintTable lintTable;

    public BurpTab() {
        initComponents();
    }

    private void initComponents() {

        // Panel that is returned.
        panel = new JSplitPane(JSplitPane.VERTICAL_SPLIT);

        topPanel = new JPanel();
        // configPanel.setBorder(BorderFactory.createBevelBorder(1));
        loadConfigButton = new JButton("Load Config");

        saveConfigButton = new JButton("Save Config");
        saveConfigButton.addActionListener(new java.awt.event.ActionListener() {
            public void actionPerformed(java.awt.event.ActionEvent evt) {
                File sf = FileChooser.saveFile(
                    panel, FileChooser.getLastWorkingDirectory(),
                    "Save config file", "json"
                );
                if (sf != null) {
                    // Set the last working directory.
                    FileChooser.setLastWorkingDirectory(sf.getParent());
                    // Save the file.
                    try {
                        extensionConfig.writeToFile(sf);
                    } catch (Exception e) {
                        //TODO: handle exception
                        StringUtils.printStackTrace(e);
                    }
                }
            }
        });

        processToggleButton = new JToggleButton("Process");
        // processToggleButton.addActionListener(new java.awt.event.ActionListener() {
        //     public void actionPerformed(java.awt.event.ActionEvent evt) {
        //         processToggleButtonActionPerformed(evt);
        //     }
        // });

        searchTextField = new JTextField();

        searchButton = new JButton("Search");
        resetButton = new JButton("Reset");
        configButton = new JButton("Create Configuration");

        topSeparator = new JSeparator(SwingConstants.VERTICAL);
        topSeparator.setMaximumSize(new Dimension(2, 30));

        GroupLayout topPanelLayout = new GroupLayout(topPanel);
        topPanel.setLayout(topPanelLayout);

        /**
         * Start GUI generated code. Do not modify.
         */
        topPanelLayout.setHorizontalGroup(
            topPanelLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(topPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(topPanelLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addGroup(topPanelLayout.createSequentialGroup()
                        .addComponent(processToggleButton, GroupLayout.PREFERRED_SIZE, 200, GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(topSeparator)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(loadConfigButton)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(saveConfigButton)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(configButton)
                        )
                    .addGroup(topPanelLayout.createSequentialGroup()
                        .addComponent(searchTextField, GroupLayout.PREFERRED_SIZE, 400, GroupLayout.PREFERRED_SIZE)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(searchButton)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)
                        .addComponent(resetButton)
                        ))
                        .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );
        topPanelLayout.setVerticalGroup(
            topPanelLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
            .addGroup(topPanelLayout.createSequentialGroup()
                .addContainerGap()
                .addGroup(topPanelLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                    .addGroup(topPanelLayout.createSequentialGroup()
                        .addGroup(topPanelLayout.createParallelGroup(GroupLayout.Alignment.LEADING)
                            .addGroup(topPanelLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                                .addComponent(loadConfigButton)
                                .addComponent(saveConfigButton)
                                .addComponent(configButton))
                            .addComponent(topSeparator)))
                    .addGroup(topPanelLayout.createSequentialGroup()
                        .addComponent(processToggleButton)
                        .addPreferredGap(LayoutStyle.ComponentPlacement.RELATED)))
                .addGroup(topPanelLayout.createParallelGroup(GroupLayout.Alignment.BASELINE)
                    .addComponent(searchTextField, GroupLayout.PREFERRED_SIZE, GroupLayout.DEFAULT_SIZE, GroupLayout.PREFERRED_SIZE)
                    .addComponent(searchButton)
                    .addComponent(resetButton))
                .addContainerGap(GroupLayout.DEFAULT_SIZE, Short.MAX_VALUE))
        );

        // Link size of buttons.
        topPanelLayout.linkSize(SwingConstants.HORIZONTAL, loadConfigButton, saveConfigButton, configButton);
        topPanelLayout.linkSize(SwingConstants.HORIZONTAL, searchButton, resetButton);

        /**
         * End GUI generated code.
         */

        lintTable = new LintTable();
        tableScrollPane = new JScrollPane(lintTable);

        panel.setLeftComponent(topPanel);
        panel.setRightComponent(tableScrollPane);
        panel.setEnabled(false); // This disables subcomponents if they inherit this from the parent and might create endless troubles for us.
    }

    // GUI Variables
    private JButton loadConfigButton;
    private JButton saveConfigButton;
    private JTextField searchTextField;
    private JButton searchButton;
    private JButton resetButton;
    private JPanel topPanel;
    private JButton configButton;
    private JToggleButton processToggleButton;
    private JSeparator topSeparator;
    private JScrollPane tableScrollPane;
}