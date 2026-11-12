// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Copyright (c) 2014-2022 The Dash Core developers
// Copyright (c) 2022-2024 The PEPEPOW Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "splashscreen.h"

#include "guiutil.h"
#include "networkstyle.h"

#include "clientversion.h"
#include "init.h"
#include "util.h"
#include "ui_interface.h"
#include "version.h"
#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

#include <QApplication>
#include <QCloseEvent>
#include <QDesktopWidget>
#include <QPainter>

namespace {
static const int SPLASH_OUTER_INSET = 8;
static const int SPLASH_TEXT_INSET = 25;
static const int SPLASH_FOOTER_HEIGHT = 159;
static const int SPLASH_MESSAGE_HEIGHT = 23;
}

SplashScreen::SplashScreen(Qt::WindowFlags f, const NetworkStyle *networkStyle) :
    QWidget(0, f), curAlignment(0)
{

    // transparent background
    setAttribute(Qt::WA_TranslucentBackground);
    setStyleSheet("background:transparent;");

    // no window decorations
    setWindowFlags(Qt::FramelessWindowHint);

    // Keep the artwork visible while giving all splash text a readable footer.
    const QString titleText = tr("PEPEPOW Core");
    const QString versionText = tr("Version %1").arg(QString::fromStdString(FormatFullVersion()));
    const QString copyrightTextBtc = QChar(0xA9) + QString(" 2009-%1 ").arg(COPYRIGHT_YEAR) + tr("The Bitcoin Core developers");
    const QString copyrightTextDash = QChar(0xA9) + QString(" 2014-%1 ").arg(COPYRIGHT_YEAR) + tr("The Dash Core developers");
    const QString copyrightTextPEPEPOW = QChar(0xA9) + QString(" 2022-%1 ").arg(COPYRIGHT_YEAR) + tr("The PEPEPOW Core developers");
    const QString titleAddText = networkStyle->getTitleAddText();

    // networkstyle.cpp cannot select a theme-aware splash image.
    QString splashScreenPath = ":/images/" + GUIUtil::getThemeName() + "/splash";
    if (GetBoolArg("-regtest", false) || GetBoolArg("-testnet", false))
        splashScreenPath = ":/images/" + GUIUtil::getThemeName() + "/splash_testnet";

    pixmap = QPixmap(splashScreenPath);
    QPainter pixPaint(&pixmap);
    pixPaint.setRenderHint(QPainter::TextAntialiasing);
    const int footerTop = pixmap.height() - SPLASH_FOOTER_HEIGHT;
    const int textWidth = pixmap.width() - 2 * SPLASH_TEXT_INSET;

    // A dark translucent footer improves contrast without replacing the artwork.
    pixPaint.fillRect(QRect(SPLASH_OUTER_INSET, footerTop,
                           pixmap.width() - 2 * SPLASH_OUTER_INSET,
                           SPLASH_FOOTER_HEIGHT - SPLASH_OUTER_INSET),
                      QColor(8, 15, 27, 208));
    pixPaint.setPen(Qt::white);

    // Derive the font from QFont, not QFont::toString() (a serialized descriptor).
    QFont footerFont = QApplication::font();
    footerFont.setPixelSize(27);
    footerFont.setBold(true);
    pixPaint.setFont(footerFont);
    QRect titleRect(SPLASH_TEXT_INSET, footerTop + 8, textWidth, 34);
    if (!titleAddText.isEmpty())
        titleRect.setWidth(textWidth * 2 / 3);
    pixPaint.drawText(titleRect, Qt::AlignLeft | Qt::AlignVCenter | Qt::TextSingleLine,
                      pixPaint.fontMetrics().elidedText(titleText, Qt::ElideRight, titleRect.width()));

    if (!titleAddText.isEmpty()) {
        footerFont.setPixelSize(12);
        pixPaint.setFont(footerFont);
        const QRect networkRect(SPLASH_TEXT_INSET + textWidth * 2 / 3, footerTop + 8,
                                textWidth / 3, 34);
        pixPaint.drawText(networkRect, Qt::AlignRight | Qt::AlignVCenter | Qt::TextSingleLine,
                          pixPaint.fontMetrics().elidedText(titleAddText, Qt::ElideRight,
                                                           networkRect.width()));
    }

    footerFont.setBold(false);
    footerFont.setPixelSize(16);
    pixPaint.setFont(footerFont);
    const QRect versionRect(SPLASH_TEXT_INSET, footerTop + 44, textWidth, 25);
    pixPaint.drawText(versionRect, Qt::AlignLeft | Qt::AlignVCenter | Qt::TextSingleLine,
                      pixPaint.fontMetrics().elidedText(versionText, Qt::ElideRight, textWidth));

    footerFont.setPixelSize(12);
    pixPaint.setFont(footerFont);
    const QString copyrightLines[] = {
        copyrightTextBtc, copyrightTextDash, copyrightTextPEPEPOW
    };
    for (int i = 0; i < 3; ++i) {
        const QRect lineRect(SPLASH_TEXT_INSET, footerTop + 75 + i * 17,
                             textWidth, 16);
        pixPaint.drawText(lineRect, Qt::AlignLeft | Qt::AlignVCenter | Qt::TextSingleLine,
                          pixPaint.fontMetrics().elidedText(copyrightLines[i],
                                                           Qt::ElideRight, textWidth));
    }
    pixPaint.end();

    // Resize window and move to center of desktop, disallow resizing
    QRect r(QPoint(), pixmap.size());
    resize(r.size());
    setFixedSize(r.size());
    move(QApplication::desktop()->screenGeometry().center() - r.center());

    subscribeToCoreSignals();
    installEventFilter(this);
}

SplashScreen::~SplashScreen()
{
    unsubscribeFromCoreSignals();
}

bool SplashScreen::eventFilter(QObject * obj, QEvent * ev) {
    if (ev->type() == QEvent::KeyPress) {
        QKeyEvent *keyEvent = static_cast<QKeyEvent *>(ev);
        if(keyEvent->text()[0] == 'q' && breakAction != nullptr) {
            breakAction();
        }
    }
    return QObject::eventFilter(obj, ev);
}

void SplashScreen::slotFinish(QWidget *mainWin)
{
    Q_UNUSED(mainWin);

    /* If the window is minimized, hide() will be ignored. */
    /* Make sure we de-minimize the splashscreen window before hiding */
    if (isMinimized())
        showNormal();
    hide();
    deleteLater(); // No more need for this
}

static void InitMessage(SplashScreen *splash, const std::string &message)
{
    QMetaObject::invokeMethod(splash, "showMessage",
        Qt::QueuedConnection,
        Q_ARG(QString, QString::fromStdString(message)),
        Q_ARG(int, Qt::AlignBottom|Qt::AlignHCenter),
        //Q_ARG(QColor, QColor(55,55,55))); 
        Q_ARG(QColor, QColor(255,255,255))); // white color text
}

static void ShowProgress(SplashScreen *splash, const std::string &title, int nProgress)
{
    InitMessage(splash, title + strprintf("%d", nProgress) + "%");
}

void SplashScreen::setBreakAction(const std::function<void(void)> &action)
{
    breakAction = action;
}

static void SetProgressBreakAction(SplashScreen *splash, const std::function<void(void)> &action)
{
    QMetaObject::invokeMethod(splash, "setBreakAction",
        Qt::QueuedConnection,
        Q_ARG(std::function<void(void)>, action));
}

#ifdef ENABLE_WALLET
static void ConnectWallet(SplashScreen *splash, CWallet* wallet)
{
    wallet->ShowProgress.connect(boost::bind(ShowProgress, splash, boost::placeholders::_1, boost::placeholders::_2));
}
#endif

void SplashScreen::subscribeToCoreSignals()
{
    // Connect signals to client
    uiInterface.InitMessage.connect(boost::bind(InitMessage, this, boost::placeholders::_1));
    uiInterface.ShowProgress.connect(boost::bind(ShowProgress, this, boost::placeholders::_1, boost::placeholders::_2));
    uiInterface.SetProgressBreakAction.connect(boost::bind(SetProgressBreakAction, this, boost::placeholders::_1));
#ifdef ENABLE_WALLET
    uiInterface.LoadWallet.connect(boost::bind(ConnectWallet, this, boost::placeholders::_1));
#endif
}

void SplashScreen::unsubscribeFromCoreSignals()
{
    // Disconnect signals from client
    uiInterface.InitMessage.disconnect(boost::bind(InitMessage, this, boost::placeholders::_1));
    uiInterface.ShowProgress.disconnect(boost::bind(ShowProgress, this, boost::placeholders::_1, boost::placeholders::_2));
#ifdef ENABLE_WALLET
    if(pwalletMain)
        pwalletMain->ShowProgress.disconnect(boost::bind(ShowProgress, this, boost::placeholders::_1, boost::placeholders::_2));
#endif
}

void SplashScreen::showMessage(const QString &message, int alignment, const QColor &color)
{
    curMessage = message;
    curAlignment = alignment;
    curColor = color;
    update();
}

void SplashScreen::paintEvent(QPaintEvent *event)
{
    Q_UNUSED(event);
    QPainter painter(this);
    painter.drawPixmap(0, 0, pixmap);

    // The bottom row is reserved for changing initialization/progress text.
    // It cannot paint over the three static copyright lines above it.
    if (curMessage.isEmpty())
        return;

    const QRect messageRect(SPLASH_TEXT_INSET, height() - 32,
                            width() - 2 * SPLASH_TEXT_INSET, SPLASH_MESSAGE_HEIGHT);
    QFont messageFont = QApplication::font();
    messageFont.setPixelSize(13);
    painter.setFont(messageFont);
    painter.setRenderHint(QPainter::TextAntialiasing);
    painter.setPen(curColor.isValid() ? curColor : QColor(Qt::white));
    const QString message = painter.fontMetrics().elidedText(curMessage,
                                                             Qt::ElideRight,
                                                             messageRect.width());
    painter.drawText(messageRect,
                     (curAlignment & Qt::AlignHorizontal_Mask) | Qt::AlignVCenter |
                         Qt::TextSingleLine,
                     message);
}

void SplashScreen::closeEvent(QCloseEvent *event)
{
    StartShutdown(); // allows an "emergency" shutdown during startup
    event->ignore();
}
