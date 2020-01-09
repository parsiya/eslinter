package linttable;

import java.util.ArrayList;
import javax.swing.table.AbstractTableModel;

import burp.Config;

/**
 * LintTableModel
 */
public class LintTableModel extends AbstractTableModel {

    private String[] columnNames;
    private Class[] columnClasses;
    private ArrayList<LintResult> lintResults;

    public LintTableModel() {
        initTableModel();
    }

    private void initTableModel() {
        // Set columns.
        columnNames = Config.lintTableColumnNames;
        columnClasses = Config.lintTableColumnClasses;
        // Create the underlying LintResults.
        lintResults = new ArrayList<LintResult>();
    }

    // Implementing AbstractTableModel.

    @Override
    public int getRowCount() {
        return lintResults.size();
    }

    @Override
    public int getColumnCount() {
        return columnNames.length;
    }

    @Override
    public Object getValueAt(int rowIndex, int columnIndex) {
        LintResult lr = lintResults.get(rowIndex);
        switch (columnIndex) {
            case 0:
                return lr.host;
            case 1:
                return lr.url;
            case 2:
                return lr.status;
            case 3:
                return lr.numResults;
        }
        return lr.host;
    }

    @Override
    public String getColumnName(int column) {
        // Returns the column name.
        return columnNames[column];
    }

    @Override
    public Class<?> getColumnClass(int columnIndex) {
        // Returns the column class.
        return columnClasses[columnIndex];
    }

    // AbstractTableModel implemented.
    
    private boolean invalidRowIndex(int index) {
        return ((index < 0) || (index >= getRowCount()));
    }

    public LintResult get(int index) throws IndexOutOfBoundsException {
        if (invalidRowIndex(index)) {
            String errorMessage = String.format("Requested index: %s - max index: %s", index, getRowCount());
            throw new IndexOutOfBoundsException(errorMessage);
        }
        return lintResults.get(index);
    }

    public void add(LintResult lr) {
        lintResults.add(lr);
        fireTableDataChanged();
    }

    public void delete(int index) {
        if (invalidRowIndex(index)) {
            String errorMessage = String.format("Requested index: %s - max index: %s", index, getRowCount());
            throw new IndexOutOfBoundsException(errorMessage);
        }
        lintResults.remove(index);
        fireTableDataChanged();
    }

    public void edit(int index, LintResult lr) throws IndexOutOfBoundsException {
        if (invalidRowIndex(index)) {
            String errorMessage = String.format("Requested index: %s - max index: %s", index, getRowCount());
            throw new IndexOutOfBoundsException(errorMessage);
        }
        lintResults.set(index, lr);
        fireTableDataChanged();
    }

    public void clear() {
        lintResults.clear();
        fireTableDataChanged();
    }

    public void populate(ArrayList<LintResult> newResults) {
        clear();
        lintResults.addAll(newResults);
        fireTableDataChanged();
    }

    public ArrayList<LintResult> getAll() {
        return lintResults;
    }

    // Returns true if a column index is invalid.
    public boolean invalidColumnIndex(int columnIndex) {
        return ((columnIndex < 0) || (columnIndex >= getColumnCount()));
    }
}