// Copyright (c) 2026 The PEPEPOW Core developers
// Distributed under the MIT software license, see the accompanying file COPYING.
#ifndef BITCOIN_QT_TEST_TRANSACTIONFILTERPROXYTESTS_H
#define BITCOIN_QT_TEST_TRANSACTIONFILTERPROXYTESTS_H
#include <QObject>
class TransactionFilterProxyTests : public QObject
{
    Q_OBJECT
private Q_SLOTS:
    void inactiveFilters();
    void activeFilters();
    void confirmationRefreshLargeHistory();
    void transactionChanges();
    void sourceReplacement();
};
#endif
