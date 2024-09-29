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

SplashScreen::SplashScreen(Qt::WindowFlags f, const NetworkStyle *networkStyle) :
    QWidget(0, f), curAlignment(0)
{

    // transparent background
    setAttribute(Qt::WA_TranslucentBackground);
    setStyleSheet("background:transparent;");

    // no window decorations
    setWindowFlags(Qt::FramelessWindowHint);

    // set reference point, paddings
    int paddingLeft             = 25;
    int paddingTop              = 440;
    int titleVersionVSpace      = 40;
    int titleCopyrightVSpace    = 50;

    float fontFactor            = 1;

    // define text to place
    QString titleText       = tr("PEPEPOW Core");
    QString versionText     = QString(tr("Version %1")).arg(QString::fromStdString(FormatFullVersion()));
    QString copyrightTextBtc   = QChar(0xA9)+QString(" 2009-%1 ").arg(COPYRIGHT_YEAR) + QString(tr("The Bitcoin Core developers"));
    QString copyrightTextDash   = QChar(0xA9)+QString(" 2014-%1 ").arg(COPYRIGHT_YEAR) + QString(tr("The Dash Core developers"));
    QString copyrightTextPEPEPOW   = QChar(0xA9)+QString(" 2022-%1 ").arg(COPYRIGHT_YEAR) + QString(tr("The PEPEPOW Core developers"));
    QString titleAddText    = networkStyle->getTitleAddText();
    // networkstyle.cpp can't (yet) read themes, so we do it here to get the correct Splash-screen
    QString splashScreenPath = ":/images/" + GUIUtil::getThemeName() + "/splash";
    if(GetBoolArg("-regtest", false))
        splashScreenPath = ":/images/" + GUIUtil::getThemeName() + "/splash_testnet";
    if(GetBoolArg("-testnet", false))
        splashScreenPath = ":/images/" + GUIUtil::getThemeName() + "/splash_testnet";

    QString font = QApplication::font().toString();

    // load the bitmap for writing some text over it
    pixmap = QPixmap(splashScreenPath);

    QPainter pixPaint(&pixmap);
    //pixPaint.setPen(QColor(100,100,100));
    pixPaint.setPen(QColor(255,255,255)); // white color text


    // check font size and drawing with
    pixPaint.setFont(QFont(font, 28*fontFactor));
    QFontMetrics fm = pixPaint.fontMetrics();
    int titleTextWidth  = fm.width(titleText);
    if(titleTextWidth > 160) {
        // strange font rendering, Arial probably not found
        fontFactor = 0.75;
    }

    pixPaint.setFont(QFont(font, 28*fontFactor));
    fm = pixPaint.fontMetrics();
    titleTextWidth  = fm.width(titleText);
    pixPaint.drawText(paddingLeft,paddingTop,titleText);

    pixPaint.setFont(QFont(font, 15*fontFactor));
    pixPaint.drawText(paddingLeft,paddingTop+titleVersionVSpace,versionText);

    // draw copyright stuff
    pixPaint.setFont(QFont(font, 10*fontFactor));
    pixPaint.drawText(paddingLeft,paddingTop+titleCopyrightVSpace+15,copyrightTextBtc);
    pixPaint.drawText(paddingLeft,paddingTop+titleCopyrightVSpace+15,copyrightTextDash);
    pixPaint.drawText(paddingLeft,paddingTop+titleCopyrightVSpace+35,copyrightTextPEPEPOW);

    // draw additional text if special network
    if(!titleAddText.isEmpty()) {
        QFont boldFont = QFont(font, 10*fontFactor);
        boldFont.setWeight(QFont::Bold);
        pixPaint.setFont(boldFont);
        fm = pixPaint.fontMetrics();
        int titleAddTextWidth  = fm.width(titleAddText);
        pixPaint.drawText(pixmap.width()-titleAddTextWidth-10,pixmap.height()-25,titleAddText);
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
    QPainter painter(this);
    painter.setPen(QColor(255, 255, 255)); // White frame
    painter.drawPixmap(0, 0, pixmap); //draw background picture
    painter.setBrush(QBrush(QColor(70, 0, 110, 30)));  // RGBA dark purple, 30 transparent
    QRect textBackgroundRect = rect().adjusted(7, 7, -7, -7);
    painter.drawRect(textBackgroundRect);  // draw rect
    painter.setPen(curColor); //font color
    painter.drawText(textBackgroundRect, curAlignment, curMessage); // print text
}

void SplashScreen::closeEvent(QCloseEvent *event)
{
    StartShutdown(); // allows an "emergency" shutdown during startup
    event->ignore();
}
