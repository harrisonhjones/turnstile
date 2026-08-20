import { IonButton, IonButtons, IonHeader, IonIcon, IonTitle, IonToolbar } from "@ionic/react";
import { logOutOutline } from "ionicons/icons";
import { useAuth } from "../auth";

// AppHeader is the shared toolbar with the page title and a sign-out button.
export default function AppHeader({ title }: { title: string }) {
  const { signOut } = useAuth();
  return (
    <IonHeader>
      <IonToolbar>
        <IonTitle>{title}</IonTitle>
        <IonButtons slot="end">
          <IonButton onClick={signOut} title="Sign out">
            <IonIcon slot="icon-only" icon={logOutOutline} />
          </IonButton>
        </IonButtons>
      </IonToolbar>
    </IonHeader>
  );
}
