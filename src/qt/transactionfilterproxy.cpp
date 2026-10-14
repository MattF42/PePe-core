// Copyright (c) 2011-2013 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "transactionfilterproxy.h"

#include "transactiontablemodel.h"
#include "transactionrecord.h"

#include <cstdlib>

#include <QDateTime>

// Earliest date that can be represented (far in the past)
const QDateTime TransactionFilterProxy::MIN_DATE = QDateTime::fromTime_t(0);
// Last date that can be represented (far in the future)
const QDateTime TransactionFilterProxy::MAX_DATE = QDateTime::fromTime_t(0xFFFFFFFF);

TransactionFilterProxy::TransactionFilterProxy(QObject *parent) :
    QSortFilterProxyModel(parent),
    dateFrom(MIN_DATE),
    dateTo(MAX_DATE),
    addrPrefix(),
    typeFilter(COMMON_TYPES),
    watchOnlyFilter(WatchOnlyFilter_All),
    minAmount(0),
    limitRows(-1),
    showInactive(true)
{
}

void TransactionFilterProxy::setSourceModel(QAbstractItemModel *model)
{
    if (sourceModel())
        disconnect(sourceModel(), SIGNAL(confirmationsChanged()), this, SLOT(refreshConfirmations()));
    QSortFilterProxyModel::setSourceModel(model);
    if (model && model->metaObject()->indexOfSignal("confirmationsChanged()") != -1)
        connect(model, SIGNAL(confirmationsChanged()), this, SLOT(refreshConfirmations()));
}

void TransactionFilterProxy::refreshConfirmations()
{
    if (rowCount() > 0 && columnCount() > 0)
        Q_EMIT dataChanged(index(0, 0), index(rowCount() - 1, columnCount() - 1));
}

bool TransactionFilterProxy::filterAcceptsRow(int sourceRow, const QModelIndex &sourceParent) const
{
    QModelIndex index = sourceModel()->index(sourceRow, 0, sourceParent);

    if (typeFilter != ALL_TYPES && !(TYPE(index.data(TransactionTableModel::TypeRole).toInt()) & typeFilter))
        return false;
    if (watchOnlyFilter != WatchOnlyFilter_All) {
        bool watchOnly = index.data(TransactionTableModel::WatchonlyRole).toBool();
        if (watchOnly != (watchOnlyFilter == WatchOnlyFilter_Yes))
            return false;
    }
    if (dateFrom != MIN_DATE || dateTo != MAX_DATE) {
        QDateTime date = index.data(TransactionTableModel::DateRole).toDateTime();
        if (date < dateFrom || date > dateTo)
            return false;
    }
    if (!addrPrefix.isEmpty() &&
        !index.data(TransactionTableModel::AddressRole).toString().contains(addrPrefix, Qt::CaseInsensitive) &&
        !index.data(TransactionTableModel::LabelRole).toString().contains(addrPrefix, Qt::CaseInsensitive))
        return false;
    if (minAmount > 0 && llabs(index.data(TransactionTableModel::AmountRole).toLongLong()) < minAmount)
        return false;
    if (!showInactive && index.data(TransactionTableModel::StatusRole).toInt() == TransactionStatus::Conflicted)
        return false;

    return true;
}

void TransactionFilterProxy::setDateRange(const QDateTime &from, const QDateTime &to)
{
    this->dateFrom = from;
    this->dateTo = to;
    invalidateFilter();
}

void TransactionFilterProxy::setAddressPrefix(const QString &addrPrefix)
{
    this->addrPrefix = addrPrefix;
    invalidateFilter();
}

void TransactionFilterProxy::setTypeFilter(quint32 modes)
{
    this->typeFilter = modes;
    invalidateFilter();
}

void TransactionFilterProxy::setMinAmount(const CAmount& minimum)
{
    this->minAmount = minimum;
    invalidateFilter();
}

void TransactionFilterProxy::setWatchOnlyFilter(WatchOnlyFilter filter)
{
    this->watchOnlyFilter = filter;
    invalidateFilter();
}

void TransactionFilterProxy::setLimit(int limit)
{
    this->limitRows = limit;
}

void TransactionFilterProxy::setShowInactive(bool showInactive)
{
    this->showInactive = showInactive;
    invalidateFilter();
}

int TransactionFilterProxy::rowCount(const QModelIndex &parent) const
{
    if(limitRows != -1)
    {
        return std::min(QSortFilterProxyModel::rowCount(parent), limitRows);
    }
    else
    {
        return QSortFilterProxyModel::rowCount(parent);
    }
}
