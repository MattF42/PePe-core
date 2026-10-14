// Copyright (c) 2026 The PEPEPOW Core developers
// Distributed under the MIT software license, see the accompanying file COPYING.
#include "transactionfilterproxytests.h"
#include "qt/transactionfilterproxy.h"
#include "qt/transactiontablemodel.h"
#include "qt/transactionrecord.h"
#include <QElapsedTimer>
#include <QMap>
#include <QSignalSpy>
#include <QTest>

// Counts source lookups, without a wallet or chain, to isolate Qt proxy work.
class CountingTransactionModel : public QAbstractTableModel
{
    Q_OBJECT
public:
    int rows;
    mutable QMap<int, int> calls;
    QMap<int, int> statuses;
    QMap<int, int> sortKeys;
    explicit CountingTransactionModel(int count) : rows(count) {}
    int rowCount(const QModelIndex &parent = QModelIndex()) const override { return parent.isValid() ? 0 : rows; }
    int columnCount(const QModelIndex & = QModelIndex()) const override { return 6; }
    QVariant data(const QModelIndex &index, int role) const override
    {
        ++calls[role];
        switch (role) {
        case TransactionTableModel::TypeRole: return TransactionRecord::RecvWithAddress;
        case TransactionTableModel::DateRole: return QDateTime::fromTime_t(1000);
        case TransactionTableModel::WatchonlyRole: return index.row() % 2 == 0;
        case TransactionTableModel::AddressRole: return QString("address");
        case TransactionTableModel::LabelRole: return QString("label");
        case TransactionTableModel::AmountRole: return qint64(-100);
        case TransactionTableModel::StatusRole: return statuses.value(index.row(), TransactionStatus::Confirmed);
        case Qt::EditRole: return sortKeys.value(index.row(), index.row());
        default: return QVariant();
        }
    }
    void confirm() { Q_EMIT confirmationsChanged(); }
    void change(int row, int status, int key)
    {
        statuses[row] = status;
        sortKeys[row] = key;
        Q_EMIT dataChanged(index(row, 0), index(row, 5));
    }
    void fullRefresh() { Q_EMIT dataChanged(index(0, 0), index(rows - 1, 5)); }
    void append()
    {
        beginInsertRows(QModelIndex(), rows, rows);
        ++rows;
        endInsertRows();
    }
    void removeLast()
    {
        beginRemoveRows(QModelIndex(), rows - 1, rows - 1);
        --rows;
        endRemoveRows();
    }
Q_SIGNALS:
    void confirmationsChanged();
};

void TransactionFilterProxyTests::inactiveFilters()
{
    CountingTransactionModel source(20);
    TransactionFilterProxy proxy;
    proxy.setSourceModel(&source);
    QCOMPARE(proxy.rowCount(), 20);
    QCOMPARE(source.calls.value(TransactionTableModel::TypeRole), 20);
    QCOMPARE(source.calls.size(), 1);
    proxy.setTypeFilter(TransactionFilterProxy::ALL_TYPES);
    source.calls.clear();
    proxy.setMinAmount(0);
    QCOMPARE(proxy.rowCount(), 20);
    QCOMPARE(source.calls.size(), 0);
}

void TransactionFilterProxyTests::activeFilters()
{
    CountingTransactionModel source(20);
    TransactionFilterProxy proxy;
    proxy.setSourceModel(&source);
    proxy.setWatchOnlyFilter(TransactionFilterProxy::WatchOnlyFilter_Yes);
    QCOMPARE(proxy.rowCount(), 10);
    proxy.setWatchOnlyFilter(TransactionFilterProxy::WatchOnlyFilter_No);
    QCOMPARE(proxy.rowCount(), 10);
    proxy.setWatchOnlyFilter(TransactionFilterProxy::WatchOnlyFilter_All);
    proxy.setDateRange(QDateTime::fromTime_t(1000), QDateTime::fromTime_t(1000));
    QCOMPARE(proxy.rowCount(), 20);
    proxy.setDateRange(QDateTime::fromTime_t(1001), TransactionFilterProxy::MAX_DATE);
    QCOMPARE(proxy.rowCount(), 0);
    proxy.setDateRange(TransactionFilterProxy::MIN_DATE, TransactionFilterProxy::MAX_DATE);
    proxy.setAddressPrefix("ADD");
    QCOMPARE(proxy.rowCount(), 20);
    proxy.setAddressPrefix("LAB");
    QCOMPARE(proxy.rowCount(), 20);
    proxy.setAddressPrefix("missing");
    QCOMPARE(proxy.rowCount(), 0);
    proxy.setAddressPrefix("");
    proxy.setMinAmount(100);
    QCOMPARE(proxy.rowCount(), 20);
    proxy.setMinAmount(101);
    QCOMPARE(proxy.rowCount(), 0);
    proxy.setMinAmount(0);
    proxy.setTypeFilter(TransactionFilterProxy::TYPE(TransactionRecord::PrivateSend));
    QCOMPARE(proxy.rowCount(), 0);
}

void TransactionFilterProxyTests::confirmationRefreshLargeHistory()
{
    CountingTransactionModel source(100000);
    TransactionFilterProxy history, overview;
    history.setSourceModel(&source);
    overview.setSourceModel(&source);
    overview.setLimit(5);
    overview.setShowInactive(false);
    for (TransactionFilterProxy *proxy : {&history, &overview}) {
        proxy->setDynamicSortFilter(true);
        proxy->setSortRole(Qt::EditRole);
        proxy->sort(TransactionTableModel::Status, Qt::DescendingOrder);
    }
    QCOMPARE(history.rowCount(), 100000);
    QCOMPARE(overview.rowCount(), 5);
    QCOMPARE(overview.index(0, 0).data(Qt::EditRole).toInt(), 99999);
    QSignalSpy historyPaint(&history, SIGNAL(dataChanged(QModelIndex,QModelIndex,QVector<int>)));
    QSignalSpy overviewPaint(&overview, SIGNAL(dataChanged(QModelIndex,QModelIndex,QVector<int>)));
    source.calls.clear();
    QElapsedTimer timing;
    timing.start();
    for (int block = 0; block < 100; ++block)
        source.confirm();
    qint64 repaintMs = timing.elapsed();
    QCOMPARE(source.calls.value(TransactionTableModel::TypeRole), 0);
    QCOMPARE(source.calls.value(TransactionTableModel::StatusRole), 0);
    QCOMPARE(source.calls.value(Qt::EditRole), 0);
    QCOMPARE(historyPaint.count(), 100);
    QCOMPARE(overviewPaint.count(), 100);
    timing.restart();
    source.fullRefresh(); // Reorg fallback still evaluates all rows.
    QVERIFY(source.calls.value(TransactionTableModel::TypeRole) >= 100000);
    qDebug() << "100k rows: 100 confirmation repaints ms=" << repaintMs
             << "one full invalidation ms=" << timing.elapsed()
             << "type lookups=" << source.calls.value(TransactionTableModel::TypeRole);
}

void TransactionFilterProxyTests::transactionChanges()
{
    CountingTransactionModel source(20);
    TransactionFilterProxy proxy;
    proxy.setSourceModel(&source);
    proxy.setDynamicSortFilter(true);
    proxy.setSortRole(Qt::EditRole);
    proxy.setShowInactive(false);
    proxy.sort(TransactionTableModel::Status, Qt::DescendingOrder);
    QCOMPARE(proxy.rowCount(), 20);
    source.change(19, TransactionStatus::Conflicted, 100);
    QCOMPARE(proxy.rowCount(), 19);
    QCOMPARE(proxy.index(0, 0).data(Qt::EditRole).toInt(), 18);
    source.change(19, TransactionStatus::Unconfirmed, 100);
    QCOMPARE(proxy.rowCount(), 20);
    QCOMPARE(proxy.index(0, 0).data(Qt::EditRole).toInt(), 100);
    source.change(19, TransactionStatus::Confirmed, -1); // confirmation changes sort key
    QCOMPARE(proxy.index(0, 0).data(Qt::EditRole).toInt(), 18);
    source.append();
    QCOMPARE(proxy.rowCount(), 21);
    QCOMPARE(proxy.index(0, 0).data(Qt::EditRole).toInt(), 20);
    source.removeLast();
    QCOMPARE(proxy.rowCount(), 20);
    // Same-height reorg refresh remains a full source data change.
    source.statuses[18] = TransactionStatus::Conflicted;
    source.fullRefresh();
    QCOMPARE(proxy.rowCount(), 19);
}

void TransactionFilterProxyTests::sourceReplacement()
{
    CountingTransactionModel first(2), second(0);
    TransactionFilterProxy proxy;
    proxy.setSourceModel(&first);
    QCOMPARE(proxy.rowCount(), 2);
    proxy.setSourceModel(&second);
    QCOMPARE(proxy.rowCount(), 0);
    first.confirm();
    second.confirm();
    second.append();
    QCOMPARE(proxy.rowCount(), 1);
    second.confirm();
    proxy.setSourceModel(nullptr);
    QCOMPARE(proxy.rowCount(), 0);
}

#ifdef TRANSACTION_PROXY_STANDALONE_TEST
QTEST_GUILESS_MAIN(TransactionFilterProxyTests)
#endif
#include "transactionfilterproxytests.moc"
