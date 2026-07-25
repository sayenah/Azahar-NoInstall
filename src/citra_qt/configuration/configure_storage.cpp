// Copyright Citra Emulator Project / Azahar Emulator Project
// Licensed under GPLv2 or any later version
// Refer to the license.txt file included.

#include <QDesktopServices>
#include <QFileDialog>
#include <QUrl>
#include "citra_qt/configuration/configure_storage.h"
#include "common/file_util.h"
#include "common/settings.h"
#include "ui_configure_storage.h"

ConfigureStorage::ConfigureStorage(bool is_powered_on_, QWidget* parent)
    : QWidget(parent), ui(std::make_unique<Ui::ConfigureStorage>()), is_powered_on{is_powered_on_} {
    ui->setupUi(this);
    SetConfiguration();

    connect(ui->open_nand_dir, &QPushButton::clicked, []() {
        QString path = QString::fromStdString(FileUtil::GetUserPath(FileUtil::UserPath::NANDDir));
        QDesktopServices::openUrl(QUrl::fromLocalFile(path));
    });

    connect(ui->change_nand_dir, &QPushButton::clicked, this, [this]() {
        ui->change_nand_dir->setEnabled(false);
        const QString dir_path = QFileDialog::getExistingDirectory(
            this, tr("Select NAND Directory"),
            QString::fromStdString(FileUtil::GetUserPath(FileUtil::UserPath::NANDDir)),
            QFileDialog::ShowDirsOnly);
        if (!dir_path.isEmpty()) {
            FileUtil::UpdateUserPath(FileUtil::UserPath::NANDDir, dir_path.toStdString());
            SetConfiguration();
        }
        ui->change_nand_dir->setEnabled(true);
    });

    connect(ui->open_sdmc_dir, &QPushButton::clicked, []() {
        QString path = QString::fromStdString(FileUtil::GetUserPath(FileUtil::UserPath::SDMCDir));
        QDesktopServices::openUrl(QUrl::fromLocalFile(path));
    });

    connect(ui->change_sdmc_dir, &QPushButton::clicked, this, [this]() {
        ui->change_sdmc_dir->setEnabled(false);
        const QString dir_path = QFileDialog::getExistingDirectory(
            this, tr("Select SDMC Directory"),
            QString::fromStdString(FileUtil::GetUserPath(FileUtil::UserPath::SDMCDir)),
            QFileDialog::ShowDirsOnly);
        if (!dir_path.isEmpty()) {
            FileUtil::UpdateUserPath(FileUtil::UserPath::SDMCDir, dir_path.toStdString());
            SetConfiguration();
        }
        ui->change_sdmc_dir->setEnabled(true);
    });

    const auto connect_content_folder = [this](QPushButton* change_button,
                                               QPushButton* clear_button, QLineEdit* path_edit,
                                               Settings::Setting<std::string>& setting,
                                               const QString& caption) {
        connect(change_button, &QPushButton::clicked, this, [this, path_edit, caption, &setting]() {
            const QString dir_path = QFileDialog::getExistingDirectory(
                this, caption, QString::fromStdString(setting.GetValue()),
                QFileDialog::ShowDirsOnly);
            if (!dir_path.isEmpty()) {
                setting = dir_path.toStdString();
                path_edit->setText(dir_path);
            }
        });
        connect(clear_button, &QPushButton::clicked, this, [path_edit, &setting]() {
            setting = std::string{};
            path_edit->clear();
        });
    };
    connect_content_folder(ui->change_updates_folder, ui->clear_updates_folder,
                           ui->updates_folder_path, Settings::values.updates_folder,
                           tr("Select Updates Folder"));
    connect_content_folder(ui->change_dlc_folder, ui->clear_dlc_folder, ui->dlc_folder_path,
                           Settings::values.dlc_folder, tr("Select DLC Folder"));
    connect_content_folder(ui->change_dsiware_folder, ui->clear_dsiware_folder,
                           ui->dsiware_folder_path, Settings::values.dsiware_folder,
                           tr("Select DSiWare Folder"));

    connect(ui->toggle_virtual_sd, &QCheckBox::clicked, this, [this]() {
        ApplyConfiguration();
        SetConfiguration();
    });
    connect(ui->toggle_custom_storage, &QCheckBox::clicked, this, [this]() {
        ApplyConfiguration();
        SetConfiguration();
    });
}

ConfigureStorage::~ConfigureStorage() = default;

void ConfigureStorage::SetConfiguration() {
    ui->nand_group->setVisible(Settings::values.use_custom_storage.GetValue());
    QString nand_path = QString::fromStdString(FileUtil::GetUserPath(FileUtil::UserPath::NANDDir));
    ui->nand_dir_path->setText(nand_path);
    ui->open_nand_dir->setEnabled(!nand_path.isEmpty());

    ui->sdmc_group->setVisible(Settings::values.use_virtual_sd &&
                               Settings::values.use_custom_storage);
    QString sdmc_path = QString::fromStdString(FileUtil::GetUserPath(FileUtil::UserPath::SDMCDir));
    ui->sdmc_dir_path->setText(sdmc_path);
    ui->open_sdmc_dir->setEnabled(!sdmc_path.isEmpty());

    ui->updates_folder_path->setText(
        QString::fromStdString(Settings::values.updates_folder.GetValue()));
    ui->dlc_folder_path->setText(QString::fromStdString(Settings::values.dlc_folder.GetValue()));
    ui->dsiware_folder_path->setText(
        QString::fromStdString(Settings::values.dsiware_folder.GetValue()));

    ui->toggle_virtual_sd->setChecked(Settings::values.use_virtual_sd.GetValue());
    ui->toggle_custom_storage->setChecked(Settings::values.use_custom_storage.GetValue());
    ui->toggle_compress_cia->setChecked(Settings::values.compress_cia_installs.GetValue());

    ui->storage_group->setEnabled(!is_powered_on);
}

void ConfigureStorage::ApplyConfiguration() {
    Settings::values.use_virtual_sd = ui->toggle_virtual_sd->isChecked();
    Settings::values.use_custom_storage = ui->toggle_custom_storage->isChecked();
    Settings::values.compress_cia_installs = ui->toggle_compress_cia->isChecked();

    if (!Settings::values.use_custom_storage) {
        FileUtil::UpdateUserPath(FileUtil::UserPath::NANDDir,
                                 GetDefaultUserPath(FileUtil::UserPath::NANDDir));
        FileUtil::UpdateUserPath(FileUtil::UserPath::SDMCDir,
                                 GetDefaultUserPath(FileUtil::UserPath::SDMCDir));
    }
}

void ConfigureStorage::RetranslateUI() {
    ui->retranslateUi(this);
}
