use eframe::egui;
use strum::{EnumIter, IntoEnumIterator};

use crate::app::App;

mod my_bitassets;
mod transfer_receive;
mod tx_builder;
pub(super) mod tx_creator;
mod utxo_creator;
mod utxo_selector;

use my_bitassets::MyBitAssets;
use transfer_receive::TransferReceive;
use tx_builder::TxBuilder;

#[derive(Default, EnumIter, Eq, PartialEq, strum::Display)]
enum Tab {
    #[default]
    #[strum(to_string = "Transfer & Receive")]
    TransferReceive,
    #[strum(to_string = "Transaction Builder")]
    TransactionBuilder,
    #[strum(to_string = "My BitAssets")]
    MyBitAssets,
}

/// The coin sub-tabs a user can reach. "My BitAssets" is not one of them: the
/// FreeBank chain rejects BitAssets at validation, so the pane can only ever
/// list nothing and offer actions that fail. The variant and pane are kept so
/// the diff against the upstream chassis stays small.
fn visible_tabs() -> impl Iterator<Item = Tab> {
    Tab::iter().filter(|tab| *tab != Tab::MyBitAssets)
}

#[cfg(test)]
mod tab_tests {
    use super::*;

    #[test]
    fn no_bitassets_sub_tab_is_offered() {
        let names: Vec<String> =
            visible_tabs().map(|tab| tab.to_string()).collect();
        assert!(
            !names.iter().any(|name| name.to_lowercase().contains("bitasset")),
            "a disabled chassis feature is still reachable: {names:?}"
        );
        assert!(names.contains(&"Transfer & Receive".to_owned()), "{names:?}");
    }
}

pub struct Coins {
    my_bitassets: MyBitAssets,
    tab: Tab,
    transfer_receive: TransferReceive,
    tx_builder: TxBuilder,
}

impl Coins {
    pub fn new(app: Option<&App>) -> Self {
        Self {
            my_bitassets: MyBitAssets,
            tab: Tab::default(),
            transfer_receive: TransferReceive::new(app),
            tx_builder: TxBuilder::default(),
        }
    }

    pub fn show(
        &mut self,
        app: Option<&App>,
        ui: &mut egui::Ui,
    ) -> anyhow::Result<()> {
        egui::Panel::top("coins_tabs").show_inside(ui, |ui| {
            ui.horizontal(|ui| {
                visible_tabs().for_each(|tab_variant| {
                    let tab_name = tab_variant.to_string();
                    ui.selectable_value(&mut self.tab, tab_variant, tab_name);
                })
            });
        });
        egui::CentralPanel::default().show_inside(ui, |ui| match self.tab {
            Tab::TransferReceive => {
                let () = self.transfer_receive.show(app, ui);
            }
            Tab::TransactionBuilder => {
                let () = self.tx_builder.show(app, ui).unwrap();
            }
            Tab::MyBitAssets => {
                self.my_bitassets.show(app, ui);
            }
        });
        Ok(())
    }
}
