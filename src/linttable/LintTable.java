package linttable;

import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.util.ArrayList;

import javax.swing.JTable;
import javax.swing.RowFilter;
import javax.swing.table.TableColumnModel;
import javax.swing.table.TableRowSorter;

/**
 * LintTable
 */
public class LintTable extends JTable implements MouseListener {

    private LintTableModel model;
    private TableRowSorter<LintTableModel> sorter;

    public LintTable() {
        model = new LintTableModel();
        initTable();
    }

    private void initTable() {

        addMouseListener(this);

        // setAutoCreateRowSorter(true);
        setModel(model);
        sorter = new TableRowSorter<LintTableModel>(model);
        setRowSorter(sorter);

        // Reduce the size of the last two columns.
        // TODO Change this if we change the table columns.
        // http://glazedlists.1045722.n5.nabble.com/Setting-JTable-column-widths-to-different-percentages-of-the-total-table-td3417756.html
        setAutoResizeMode(JTable.AUTO_RESIZE_ALL_COLUMNS);
        TableColumnModel colModel = getColumnModel();
        // This works, not sure why but it works.
        colModel.getColumn(0).setPreferredWidth(2000);
        colModel.getColumn(1).setPreferredWidth(6000);
        colModel.getColumn(2).setPreferredWidth(1500);
        colModel.getColumn(3).setPreferredWidth(900);
    }

    public int getTableSelectedRow() {
        return convertRowIndexToModel(getSelectedRow());
    }

    public LintResult get(int index) {
        return model.get(index);
    }

    public LintResult getSelectedResult() {
        return get(getTableSelectedRow());
    }

    public void add(LintResult lr) {
        model.add(lr);
    }

    public void delete(int index) {
        model.delete(index);
    }

    public void clear() {
        model.clear();
    }

    public ArrayList<LintResult> getAll() {
        return model.getAll();
    }

    // Filters column with columnIndex by text.
    // https://docs.oracle.com/javase/tutorial/uiswing/examples/components/TableFilterDemoProject/src/components/TableFilterDemo.java
    public void filter(String text, int columnIndex) throws IndexOutOfBoundsException {

        // Check if column is invalid.
        if (model.invalidColumnIndex(columnIndex)) {
            // If column is invalid throw an exception.
            String errorMessage =
                String.format("Requested column index: %s - max column index: %s", columnIndex, model.getColumnCount());
            throw new IndexOutOfBoundsException(errorMessage);
        }
        
        RowFilter<LintTableModel, Object> rf = null;
        // If the current expression doesn't parse, don't update.
        try {
            rf = RowFilter.regexFilter(text, columnIndex);
            
        } catch (java.util.regex.PatternSyntaxException e) {
            return;
        }
        sorter.setRowFilter(rf);
    }


    // Implementing MouseListener.

    @Override
    public void mouseClicked(MouseEvent e) {
        // TODO implement this.
    }

    @Override
    public void mousePressed(MouseEvent e) {}

    @Override
    public void mouseReleased(MouseEvent e) {}

    @Override
    public void mouseEntered(MouseEvent e) {}

    @Override
    public void mouseExited(MouseEvent e) {}

    
}